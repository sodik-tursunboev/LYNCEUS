"""FastAPI app. Serve with `python tasks.py serve`: loopback only, no access log.

Controls (SPEC section 9, M1 amendments): bearer token, rate limit, counted body cap per route,
trusted Host header, no CORS, no served docs, a cap on parsers running at once. Nothing here takes
a fetch option: analysis is offline.
"""

import asyncio
import json
import logging
import math
import secrets
import threading
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from core.config import Settings
from core.contracts import EventSource
from core.db import audit
from core.db.store import save_analysis, save_email_analysis
from core.detection.engine import ENGINE_VERSION, UrlReport
from core.email import engine as email_engine
from core.email.engine import EmailReport
from core.intel.analyze import analyze_with_intel, link_analyzer
from core.intel.feeds import FEEDS, FeedStore, feed_status
from core.intel.registry import build_intel
from core.log import configure

log = logging.getLogger(__name__)
EMAIL_PATH = "/v1/emails/analyze"
_MESSAGE_TYPES = ("message/rfc822", "application/octet-stream")


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str


class Skipped(BaseModel):
    provider: str
    reason: str


class AnalyzeResponse(UrlReport):
    persisted: bool  # False when storage is off or failed; the verdict still stands
    intel_skipped: list[Skipped]  # providers that were enabled but not asked, and why


class ProviderHealth(BaseModel):
    provider: str
    sends: str
    breaker: str
    usable: bool


class FeedHealth(BaseModel):
    feed: str
    downloaded: bool
    entries: int
    age_hours: float | None
    stale: bool


class IntelHealth(BaseModel):
    providers: list[ProviderHealth]
    feeds: list[FeedHealth]


class EmailResponse(EmailReport):
    persisted: bool


class BodyLimit:
    """Cap the raw request body by counting it: a Content-Length header can lie or be absent."""

    def __init__(self, app: ASGIApp, default: int, per_path: dict[str, int]) -> None:
        self.app, self.default, self.per_path = app, default, per_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.per_path.get(scope["path"], self.default)
        seen = 0

        async def counted() -> Message:
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > limit:
                raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "request body too large")
            return message

        await self.app(scope, counted, send)


class RateLimit:
    # ponytail: one fixed window per process. One local caller today; per-client when that changes.
    def __init__(self, per_minute: int) -> None:
        self.limit = per_minute
        self._lock = threading.Lock()
        self._window, self._used = time.monotonic(), 0

    def __call__(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now - self._window >= 60:
                self._window, self._used = now, 0
            self._used += 1
            if self._used <= self.limit:
                return
            wait = math.ceil(60 - (now - self._window))
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "rate limit", headers={"Retry-After": str(wait)}
        )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure(settings.log_level)
    app = FastAPI(
        title="MIRAGE", version=ENGINE_VERSION, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.add_middleware(
        BodyLimit,
        default=settings.max_body_bytes,
        per_path={EMAIL_PATH: settings.max_message_bytes},
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    token = settings.api_token.get_secret_value().encode() if settings.api_token else None
    db = (
        create_engine(
            settings.database_url.get_secret_value(), pool_pre_ping=True, hide_parameters=True
        )
        if settings.database_url
        else None
    )
    intel = build_intel(settings)  # None unless the operator named providers; a typo stops start-up
    feed_store = FeedStore(settings.data_dir / "feeds")
    if intel is not None and db is not None:
        for p in intel.providers:
            try:
                audit.record(
                    db,
                    "operator",
                    "intel.enable",
                    "provider",
                    {"provider": p.name, "sends": p.sends.value},
                )
            except Exception:  # noqa: BLE001  (the audit table may not exist yet; the log line remains)
                log.warning("could not write the intelligence audit record")
    bearer = HTTPBearer(auto_error=False)
    limiter = RateLimit(settings.rate_limit_per_minute)
    parser_slots = asyncio.Semaphore(settings.max_concurrent_parsers)

    def require_token(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> None:
        if token is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API token not configured")
        given = credentials.credentials.encode() if credentials else b""
        if not secrets.compare_digest(given, token):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/urls/analyze", dependencies=[Depends(require_token), Depends(limiter)])
    async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
        analysis, outcome = await analyze_with_intel(request.url, intel)
        persisted = False
        if db is not None:
            try:
                await run_in_threadpool(save_analysis, db, analysis, EventSource.API)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist analysis")
        skipped = [Skipped(provider=n, reason=why) for n, why in outcome.skipped]
        report = analysis.report().model_dump()
        return AnalyzeResponse(**report, persisted=persisted, intel_skipped=skipped)

    @app.get("/v1/intel/health", dependencies=[Depends(require_token)])
    def intel_health() -> IntelHealth:
        enabled = settings.intel_enabled() & FEEDS.keys()
        feeds = feed_status(feed_store, enabled, datetime.now(UTC))
        return IntelHealth(
            providers=[ProviderHealth(**h) for h in (intel.health() if intel else [])],
            feeds=[FeedHealth(**f) for f in feeds],
        )

    @app.post(
        EMAIL_PATH,
        dependencies=[Depends(require_token), Depends(limiter)],
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}},
            }
        },
    )
    async def analyze_email(request: Request) -> EmailResponse:
        media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type not in _MESSAGE_TYPES:
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "send message/rfc822")
        raw = await request.body()
        try:
            await asyncio.wait_for(parser_slots.acquire(), timeout=1.0)
        except TimeoutError:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "all parsers are busy",
                headers={"Retry-After": "2"},
            ) from None
        try:
            links = link_analyzer(intel) if intel is not None else None
            analyze = partial(email_engine.analyze_message, raw, link_analyzer=links)
            analysis = await run_in_threadpool(analyze)
            persisted = False
            if db is not None:
                try:
                    await run_in_threadpool(save_email_analysis, db, analysis, EventSource.API)
                    persisted = True
                except Exception:  # a storage failure must not cost the caller the verdict
                    log.exception("could not persist message analysis")
        finally:
            parser_slots.release()
        return EmailResponse(**analysis.report.model_dump(), persisted=persisted)

    return app


if __name__ == "__main__":  # python -m core.api.app: refresh docs/openapi.json
    schema = create_app(Settings(_env_file=None)).openapi()
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    Path("docs/openapi.json").write_text(text, encoding="utf-8", newline="\n")
