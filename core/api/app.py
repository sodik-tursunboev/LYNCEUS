"""FastAPI app. Serve with `python tasks.py serve`: loopback only, no access log.

Controls (SPEC section 9, M1 amendments): bearer token, rate limit, counted body cap per route,
trusted Host header, no CORS, no served docs, a cap on parsers running at once. Nothing here takes
a fetch option: analysis is offline.
"""

import asyncio
import hmac
import json
import logging
import math
import re
import secrets
import threading
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Annotated
from urllib.parse import unquote

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import create_engine
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from core import hashlists
from core.api.console import mount_console
from core.config import Settings, legacy_env_names
from core.contracts import EventSource, VerdictState
from core.db import audit
from core.db.store import save_analysis, save_email_analysis, save_file_analysis
from core.detection.engine import ENGINE_VERSION, UrlAnalysis, UrlReport
from core.detonate import PageReport, detonate_url, safe_screenshot
from core.email import engine as email_engine
from core.email.engine import EmailReport
from core.files.engine import FileReport, analyze_file
from core.intel.analyze import analyze_with_intel, link_analyzer
from core.intel.feeds import FEEDS, FeedStore, feed_status
from core.intel.refresh import feed_keys, keep_fresh
from core.intel.registry import build_intel
from core.llm.build import build_advisor
from core.log import configure
from core.mailbox.quarantine import MailQuarantineRunner
from core.mailbox.service import MailboxService, combined_status
from core.mailbox.wiring import build_mailboxes, build_quarantine
from core.response import service as response_service
from core.response.routes import build_router as response_router
from core.urls.parse import ParsedUrl, parse_url

log = logging.getLogger(__name__)
EMAIL_PATH = "/v1/emails/analyze"
FILE_PATH = "/v1/files/analyze"
_MESSAGE_TYPES = ("message/rfc822", "application/octet-stream")


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str


class Skipped(BaseModel):
    provider: str
    reason: str


class UrlAnatomy(BaseModel):
    """How the analysed URL splits into parts, for the console's "anatomy" view. Echoes the caller's
    own input back to them (the password, if any, is never included); nothing here is logged or
    stored."""

    scheme: str
    username: str | None  # the text before "@": often the deception itself (paypal.com@evil.test)
    has_password: bool
    host: str | None
    host_unicode: str | None
    host_kind: str
    subdomain: str
    registered_domain: str | None
    public_suffix: str | None
    private_suffix: bool
    port: int | None
    path: str
    query: str
    fragment: str


class AnalyzeResponse(UrlReport):
    persisted: bool  # False when storage is off or failed; the verdict still stands
    intel_skipped: list[Skipped]  # providers that were enabled but not asked, and why
    anatomy: UrlAnatomy | None = None  # None when the input could not be parsed as a URL


class PageSummary(BaseModel):
    """What the sandboxed browser saw (D1). Shown to the caller once; not stored."""

    status: str  # ok, partial, dead, error
    error: str | None
    http_status: int | None
    final_url: str
    chain_hosts: list[str]  # hosts of the redirect chain, in order
    title: str
    forms: int
    password_fields: int
    markers: list[str]
    downloads: list[str]  # extensions of downloads the page tried to start (none were kept)
    hosts_contacted: int
    tls_valid_from: int | None
    screenshot_jpeg: str | None  # base64, re-encoded in the parser sandbox
    elapsed_ms: int


class DetonateResponse(AnalyzeResponse):
    page: PageSummary


def anatomy_of(u: ParsedUrl | None) -> UrlAnatomy | None:
    if u is None:
        return None
    return UrlAnatomy(
        scheme=u.scheme, username=u.username, has_password=u.has_password, host=u.host,
        host_unicode=u.host_unicode, host_kind=str(u.host_kind.value), subdomain=u.subdomain,
        registered_domain=u.registered_domain, public_suffix=u.public_suffix,
        private_suffix=u.private_suffix, port=u.port, path=u.path, query=u.query,
        fragment=u.fragment,
    )  # fmt: skip


def page_summary(r: PageReport) -> PageSummary:
    hosts: list[str] = []
    for url in r.chain:
        parsed = parse_url(url)
        host = parsed.host if isinstance(parsed, ParsedUrl) else None
        if host and (not hosts or hosts[-1] != host):
            hosts.append(host)
    return PageSummary(
        status=r.status, error=r.error, http_status=r.http_status, final_url=r.final_url,
        chain_hosts=hosts, title=r.title, forms=len(r.forms),
        password_fields=sum(f.type == "password" for f in r.fields()), markers=list(r.markers),
        downloads=[d.ext for d in r.downloads], hosts_contacted=len(r.hosts),
        tls_valid_from=r.tls.valid_from if r.tls else None,
        screenshot_jpeg=safe_screenshot(r.screenshot), elapsed_ms=r.elapsed_ms,
    )  # fmt: skip


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


class FileResponse(FileReport):
    persisted: bool
    action_id: uuid.UUID | None = None  # the pending response the engine proposed, if any
    allow_listed: bool = False  # this exact file was marked "do not flag again" by the user


class FileCheck(BaseModel):
    """What the agent knows about a file it did not send (too big, or not an openable type)."""

    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(max_length=1024)]
    size: Annotated[int, Field(ge=0, le=2**50)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")]
    magic: Annotated[str, Field(max_length=16)] | None = None
    origin_host: Annotated[str, Field(max_length=253)] | None = None
    file_ref: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")] | None = None  # the agent's file id


class OverrideRequest(BaseModel):
    """The user chose to continue to a page the extension warned about (decision D5)."""

    model_config = ConfigDict(extra="forbid")

    url: Annotated[str, Field(min_length=1, max_length=8192)]
    minutes: Annotated[int, Field(ge=1, le=60)] = 15
    state: str | None = Field(default=None, max_length=16)  # the verdict that was overridden


class OverrideResponse(BaseModel):
    recorded: bool
    expires_at: datetime
    stored_in: str


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


def _file_ref(value: str | None) -> str | None:
    """The agent's opaque file id, or None if absent or malformed (then it is just not linked)."""
    return value if value and re.fullmatch(r"[0-9a-f]{32}", value) else None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure(settings.log_level)
    if old := legacy_env_names():  # names only, never values
        log.warning(
            "settings still use the old MIRAGE_ names (%s): rename them to LYNCEUS_", ", ".join(old)
        )
    intel = build_intel(settings)  # None unless the operator named providers; a typo stops start-up
    feed_store = FeedStore(settings.data_dir / "feeds")
    feed_names = sorted(settings.intel_enabled() & FEEDS.keys())  # the lists to keep downloaded
    advisor = build_advisor(settings)  # None unless the local model review is on (ADR-023)

    mailboxes: list[MailboxService] = []  # filled below, once the database exists
    quarantine: list[MailQuarantineRunner] = []  # M6b: at most one, carries out approved mail moves

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        for service in mailboxes:
            service.start()
        for runner in quarantine:
            runner.start()
        refresh = (
            asyncio.create_task(keep_fresh(feed_store, feed_names, feed_keys(settings)))
            if feed_names
            else None
        )
        yield
        if refresh is not None:
            refresh.cancel()
            await asyncio.gather(refresh, return_exceptions=True)
        for runner in quarantine:
            await run_in_threadpool(runner.stop)
        for service in mailboxes:
            await run_in_threadpool(service.stop)
        if intel is not None:
            await intel.aclose()
        if advisor is not None:
            await advisor.aclose()

    app = FastAPI(
        title="Lynceus",
        version=ENGINE_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(
        BodyLimit,
        default=settings.max_body_bytes,
        per_path={
            EMAIL_PATH: settings.max_message_bytes,
            FILE_PATH: settings.max_file_bytes,
        },
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
    mailboxes.extend(build_mailboxes(settings, db, intel))  # only what the operator enabled
    runner = build_quarantine(mailboxes, db)
    if runner is not None:
        quarantine.append(runner)
    hashlists.configure(settings.data_dir / "hashes")  # known-bad file hashes (offline lookup)
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
    url_limiter = RateLimit(settings.url_rate_limit_per_minute)
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

    mount_console(app, settings.console_dir)  # only if the console has been built
    app.include_router(
        response_router(db, require_token, RateLimit(settings.rate_limit_per_minute * 5))
    )

    @app.get("/health")
    def health(
        nonce: Annotated[str | None, Query(pattern=r"^[0-9a-f]{16,64}$")] = None,
    ) -> dict[str, str]:
        """Open to anyone, but it can prove who it is: given a nonce it also returns an HMAC of it
        keyed with the API token. The agent checks that before it sends the token, URLs or files to
        whatever is listening on the port (any local program can bind a port the real core left)."""
        body = {"status": "ok"}
        if nonce is not None and token is not None:
            body["proof"] = hmac.new(token, nonce.encode(), "sha256").hexdigest()
        return body

    @app.post("/v1/urls/analyze", dependencies=[Depends(require_token), Depends(url_limiter)])
    async def analyze(
        request: AnalyzeRequest,
        x_lynceus_source: Annotated[str | None, Header()] = None,
    ) -> AnalyzeResponse:
        analysis, outcome = await analyze_with_intel(request.url, intel)
        persisted = False
        # the browser extension says so; anything else is recorded as a plain API call
        source = EventSource.BROWSER if x_lynceus_source == "BROWSER" else EventSource.API
        if db is not None:
            try:
                await run_in_threadpool(save_analysis, db, analysis, source)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist analysis")
        skipped = [Skipped(provider=n, reason=why) for n, why in outcome.skipped]
        report = analysis.report().model_dump()
        anatomy = anatomy_of(analysis.url)
        return AnalyzeResponse(
            **report, persisted=persisted, intel_skipped=skipped, anatomy=anatomy
        )

    detonate_limiter = RateLimit(settings.detonation_per_minute)

    @app.post("/v1/urls/detonate", dependencies=[Depends(require_token), Depends(detonate_limiter)])
    async def detonate(request: AnalyzeRequest) -> DetonateResponse:
        """D1: the URL verdict, then the page opened in the sandboxed browser container, then one
        verdict over both. Off unless LYNCEUS_DETONATION is set: it visits the page from this
        computer's internet connection."""
        if not settings.detonation:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "page detonation is off")
        start, outcome = await analyze_with_intel(request.url, intel)
        analysis: UrlAnalysis
        analysis, page = await run_in_threadpool(detonate_url, request.url, start)
        persisted = False
        if db is not None:
            try:
                await run_in_threadpool(save_analysis, db, analysis, EventSource.API)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist analysis")
        summary = await run_in_threadpool(page_summary, page)
        return DetonateResponse(
            **analysis.report().model_dump(), persisted=persisted,
            intel_skipped=[Skipped(provider=n, reason=why) for n, why in outcome.skipped],
            anatomy=anatomy_of(analysis.url), page=summary,
        )  # fmt: skip

    @app.get("/v1/mailbox/status", dependencies=[Depends(require_token)])
    def mailbox_status() -> dict[str, object]:
        """Counts and states only: never an address, a subject or a token."""
        return combined_status(mailboxes)

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
        finally:
            parser_slots.release()
        if advisor is not None:  # advice only, never raises; no parser slot is held while it reads
            analysis = await advisor.advise_message(analysis, raw)
        persisted = False
        if db is not None:
            try:
                await run_in_threadpool(save_email_analysis, db, analysis, EventSource.API)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist message analysis")
        return EmailResponse(**analysis.report.model_dump(), persisted=persisted)

    async def _file_verdict(
        name: str,
        size: int,
        sha256: str,
        data: bytes | None,
        magic: str | None,
        host: str | None,
        file_ref: str | None = None,
    ) -> FileResponse:
        try:
            await asyncio.wait_for(parser_slots.acquire(), timeout=1.0)
        except TimeoutError:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "all parsers are busy",
                headers={"Retry-After": "2"},
            ) from None
        try:
            analyze = partial(
                analyze_file, name, size, sha256, data, claimed_magic=magic, origin_host=host
            )
            analysis = await run_in_threadpool(analyze)
        finally:
            parser_slots.release()
        if advisor is not None and data is not None:  # advice only, never raises (see above)
            analysis = await advisor.advise_file(analysis, data)
        persisted = False
        if db is not None:
            try:
                await run_in_threadpool(save_file_analysis, db, analysis, EventSource.AGENT)
                persisted = True
            except Exception:  # a storage failure must not cost the caller the verdict
                log.exception("could not persist file analysis")
        action_id: uuid.UUID | None = None
        allowed = False
        if persisted and db is not None:
            try:  # proposed only for a stored MALICIOUS verdict of a file not allow-listed
                allowed = await run_in_threadpool(
                    response_service.allow_listed, db, analysis.sha256
                )
                if (
                    file_ref
                    and not allowed
                    and analysis.report.verdict.state is VerdictState.MALICIOUS
                ):
                    action_id = await run_in_threadpool(
                        response_service.create_pending,
                        db, analysis.report.verdict.id, file_ref, analysis.sha256,
                    )  # fmt: skip
            except Exception:  # the verdict stands even if the response could not be recorded
                log.exception("could not record the proposed response")
        return FileResponse(
            **analysis.report.model_dump(),
            persisted=persisted,
            action_id=action_id,
            allow_listed=allowed,
        )

    @app.post(
        FILE_PATH,
        dependencies=[Depends(require_token), Depends(limiter)],
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
                },
            }
        },
    )
    async def analyze_file_bytes(request: Request) -> FileResponse:
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != (
            "application/octet-stream"
        ):
            raise HTTPException(
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "send application/octet-stream"
            )
        raw_name = request.headers.get("x-lynceus-name", "")
        name = unquote(raw_name, errors="replace")
        if not raw_name or len(raw_name) > 4096 or len(name) > 1024 or "\x00" in name:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "X-Lynceus-Name is required")
        data = await request.body()
        return await _file_verdict(
            name, len(data), request.headers.get("x-lynceus-sha256", ""), data, None,
            request.headers.get("x-lynceus-origin-host"),
            _file_ref(request.headers.get("x-lynceus-file-id")),
        )  # fmt: skip

    @app.post("/v1/files/check", dependencies=[Depends(require_token), Depends(limiter)])
    async def check_file(body: FileCheck) -> FileResponse:
        return await _file_verdict(
            body.name, body.size, body.sha256, None, body.magic, body.origin_host, body.file_ref
        )

    @app.post("/v1/overrides", dependencies=[Depends(require_token), Depends(limiter)])
    async def record_override(body: OverrideRequest) -> OverrideResponse:
        parsed = parse_url(body.url)
        if not isinstance(parsed, ParsedUrl):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "not a URL that can be analysed"
            )
        expires = datetime.now(UTC) + timedelta(minutes=body.minutes)
        detail = {
            "host": parsed.host, "url_sha256": parsed.url_sha256, "minutes": body.minutes,
            "overridden_state": body.state, "expires_at": expires.isoformat(),
        }  # fmt: skip
        try:
            where = await run_in_threadpool(
                audit.record_anywhere,
                db,
                settings.data_dir,
                "user",
                "override.grant",
                "url",
                detail,
            )
        except Exception:
            log.exception("could not write the override audit record")
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "the override could not be recorded"
            ) from None
        return OverrideResponse(recorded=True, expires_at=expires, stored_in=where)

    return app


if __name__ == "__main__":  # python -m core.api.app: refresh docs/openapi.json
    schema = create_app(Settings(_env_file=None)).openapi()
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    Path("docs/openapi.json").write_text(text, encoding="utf-8", newline="\n")
