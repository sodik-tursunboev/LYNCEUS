"""FastAPI app. Serve with `python tasks.py serve`: loopback only, no access log.

Controls (SPEC §9, M1 amendments): bearer token, rate limit, raw body cap, trusted Host header, no
CORS, no served docs. Nothing here takes a fetch option: analysis is offline.
"""

import json
import logging
import math
import secrets
import threading
import time
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from core.config import Settings
from core.contracts import EventSource
from core.db.store import save_analysis
from core.detection.engine import ENGINE_VERSION, UrlReport, analyze_url
from core.log import configure

log = logging.getLogger(__name__)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str


class AnalyzeResponse(UrlReport):
    persisted: bool  # False when storage is off or failed; the verdict still stands


class BodyLimit:
    """Cap the raw request body by counting it: a Content-Length header can lie or be absent."""

    def __init__(self, app: ASGIApp, limit: int) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        seen = 0

        async def counted() -> Message:
            nonlocal seen
            message = await receive()
            seen += len(message.get("body", b""))
            if seen > self.limit:
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
    app.add_middleware(BodyLimit, limit=settings.max_body_bytes)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    token = settings.api_token.get_secret_value().encode() if settings.api_token else None
    db = (
        create_engine(
            settings.database_url.get_secret_value(), pool_pre_ping=True, hide_parameters=True
        )
        if settings.database_url
        else None
    )
    bearer = HTTPBearer(auto_error=False)

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

    @app.post(
        "/v1/urls/analyze",
        dependencies=[Depends(require_token), Depends(RateLimit(settings.rate_limit_per_minute))],
    )
    def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
        analysis = analyze_url(request.url)
        persisted = False
        if db is not None:
            try:
                save_analysis(db, analysis, EventSource.API)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist analysis")
        return AnalyzeResponse(**analysis.report().model_dump(), persisted=persisted)

    return app


if __name__ == "__main__":  # python -m core.api.app: refresh docs/openapi.json
    schema = create_app(Settings(_env_file=None)).openapi()
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    Path("docs/openapi.json").write_text(text, encoding="utf-8", newline="\n")
