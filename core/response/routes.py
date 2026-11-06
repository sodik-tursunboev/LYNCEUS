"""HTTP routes for responses, events, the allow list and the audit log (M6, ADR-018).

All need the API token. They exist only with a database. Nothing here deletes anything, and nothing
returns a path or a file name: the core never has them.
"""

import re
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine

from core.response import service
from core.response.machine import Event

_SHA = re.compile(r"^[0-9a-f]{64}$")


class ActionOut(BaseModel):
    id: uuid.UUID
    verdict_id: uuid.UUID
    kind: str
    provider: str | None = None  # gmail or outlook, for email actions (never the message id)
    state: str
    file_ref: str
    sha256: str
    decided_by: str | None
    reason: str | None
    created_at: datetime
    decided_at: datetime | None
    finished_at: datetime | None
    verdict_state: str
    risk_score: int | None


class ActionResult(BaseModel):
    id: uuid.UUID
    state: str
    changed: bool  # False means it was already so: nothing was done twice


class ResultBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["applied", "failed", "restored", "restore_failed"]
    reason: Annotated[str, Field(pattern=r"^[a-z0-9_]{1,64}$")] | None = None


class EventOut(BaseModel):
    id: uuid.UUID
    kind: str
    host: str | None
    source: str
    state: str
    risk_score: int | None
    created_at: datetime
    recommended: str
    applied: str
    explanation: str
    rules: list[str]
    action_id: uuid.UUID | None
    action_state: str | None


class EventDetail(EventOut):
    signals: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    providers: list[dict[str, Any]]


class AllowBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    days: Annotated[int, Field(ge=1, le=3650)] | None = None  # None = until removed


class AllowOut(BaseModel):
    sha256: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None


class AuditOut(BaseModel):
    id: uuid.UUID
    at: datetime
    actor: str
    action: str
    target_type: str
    target_id: uuid.UUID | None
    detail: dict[str, Any] | None


def _actor(header: str | None) -> str:
    return header if header in ("user", "policy") else "user"


def build_router(
    db: Engine | None, require_token: Callable[..., None], limiter: Callable[..., None]
) -> APIRouter:
    router = APIRouter(dependencies=[Depends(require_token), Depends(limiter)])

    def need_db() -> Engine:
        if db is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "responses need the database (MIRAGE_DATABASE_URL)",
            )
        return db

    def apply(
        action_id: uuid.UUID, event: Event, actor: str, reason: str | None = None
    ) -> ActionResult:
        t = service.transition(need_db(), action_id, event, actor, reason)
        if not t.found:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such action")
        if not t.legal:
            raise HTTPException(status.HTTP_409_CONFLICT, f"not possible from {t.state}")
        return ActionResult(id=action_id, state=t.state or "", changed=t.changed)

    @router.get("/v1/events")
    def events(
        state: Annotated[str | None, Query(pattern=r"^[A-Z]{1,16}$")] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[EventOut]:
        return [EventOut(**e) for e in service.list_events(need_db(), state, limit)]

    @router.get("/v1/events/{verdict_id}")
    def event(verdict_id: uuid.UUID) -> EventDetail:
        found = service.event_detail(need_db(), verdict_id)
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such event")
        return EventDetail(**found)

    @router.get("/v1/actions")
    def actions(
        state: Annotated[str | None, Query(pattern=r"^[A-Z_,]{1,120}$")] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
        kind: Annotated[str | None, Query(pattern=r"^[A-Z_]{1,24}$")] = None,
    ) -> list[ActionOut]:
        states = [s for s in (state or "").split(",") if s] or None
        return [ActionOut(**a) for a in service.list_actions(need_db(), states, limit, kind)]

    @router.get("/v1/actions/{action_id}")
    def action(action_id: uuid.UUID) -> ActionOut:
        found = service.get_action(need_db(), action_id)
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such action")
        return ActionOut(**found)

    @router.post("/v1/actions/{action_id}/approve")
    def approve(
        action_id: uuid.UUID, x_mirage_actor: Annotated[str | None, Header()] = None
    ) -> ActionResult:
        actor = _actor(x_mirage_actor)
        if actor == "policy" and service.action_kind(need_db(), action_id) == "MAIL_QUARANTINE":
            # a wrong message move costs more than a wrong file move: always your own click
            raise HTTPException(
                status.HTTP_409_CONFLICT, "an email is moved only when you approve it yourself"
            )
        return apply(action_id, Event.APPROVE, actor)

    @router.post("/v1/actions/{action_id}/dismiss")
    def dismiss(
        action_id: uuid.UUID, x_mirage_actor: Annotated[str | None, Header()] = None
    ) -> ActionResult:
        return apply(action_id, Event.DISMISS, _actor(x_mirage_actor))

    @router.post("/v1/actions/{action_id}/restore")
    def restore(
        action_id: uuid.UUID, x_mirage_actor: Annotated[str | None, Header()] = None
    ) -> ActionResult:
        return apply(action_id, Event.RESTORE, _actor(x_mirage_actor))

    @router.post("/v1/actions/{action_id}/result")
    def result(action_id: uuid.UUID, body: ResultBody) -> ActionResult:
        """What the agent did. Only the agent reports this; the console cannot claim a result."""
        if service.action_kind(need_db(), action_id) == "MAIL_QUARANTINE":
            # the agent never handles email: only the core finishes these, in-process
            raise HTTPException(
                status.HTTP_409_CONFLICT, "an email action is finished by the core, not reported"
            )
        event_for = {
            "applied": Event.APPLIED, "failed": Event.FAILED, "restored": Event.RESTORED,
            "restore_failed": Event.RESTORE_FAILED,
        }  # fmt: skip
        return apply(action_id, event_for[body.outcome], "agent", body.reason)

    @router.get("/v1/allowlist")
    def allow_list() -> list[AllowOut]:
        return [AllowOut(**a) for a in service.allow_list(need_db())]

    @router.post("/v1/allowlist")
    def allow_add(
        body: AllowBody, x_mirage_actor: Annotated[str | None, Header()] = None
    ) -> AllowOut:
        actor = _actor(x_mirage_actor)
        service.allow_add(need_db(), body.sha256, actor, body.days)
        entry = next(a for a in service.allow_list(need_db()) if a["sha256"] == body.sha256)
        return AllowOut(**entry)

    @router.delete("/v1/allowlist/{sha256}")
    def allow_remove(
        sha256: str, x_mirage_actor: Annotated[str | None, Header()] = None
    ) -> dict[str, bool]:
        if not _SHA.match(sha256):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "not a SHA-256")
        return {"removed": service.allow_remove(need_db(), sha256, _actor(x_mirage_actor))}

    @router.get("/v1/audit")
    def audit(limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[AuditOut]:
        return [AuditOut(**a) for a in service.list_audit(need_db(), limit)]

    return router
