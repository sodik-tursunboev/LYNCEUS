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
    feedback: str | None = None  # what you said about this verdict (H1 B3)


class FeedbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: Literal["false_alarm", "missed", "correct"]


class RuleFeedback(BaseModel):
    rule_id: str
    false_alarm: int
    correct: int
    missed: int


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


def build_router(
    db: Engine | None, require_token: Callable[..., str], limiter: Callable[..., None]
) -> APIRouter:
    router = APIRouter(dependencies=[Depends(require_token), Depends(limiter)])

    def actor(
        caller: Annotated[str, Depends(require_token)],
        x_lynceus_actor: Annotated[str | None, Header()] = None,
    ) -> str:
        """Who decided. A console session is always the person at the console (H1 A1); only the
        agent's own credential may say `policy` (auto mode)."""
        if caller != "agent":
            return "user"
        return x_lynceus_actor if x_lynceus_actor in ("user", "policy") else "user"

    def agent_only(caller: Annotated[str, Depends(require_token)]) -> None:
        if caller != "agent":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only the agent reports what it did")

    def need_db() -> Engine:
        if db is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "responses need the database (LYNCEUS_DATABASE_URL)",
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

    @router.post("/v1/events/{verdict_id}/feedback")
    def feedback(
        verdict_id: uuid.UUID, body: FeedbackBody, who: Annotated[str, Depends(actor)]
    ) -> dict[str, str]:
        """Your answer about a verdict: a false alarm, a missed phishing, or right (H1 B3)."""
        if who != "user":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only a person gives feedback")
        if not service.give_feedback(need_db(), verdict_id, body.label):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such event")
        return {"label": body.label}

    @router.get("/v1/feedback/rules")
    def feedback_rules() -> list[RuleFeedback]:
        """Per rule, how often you called its verdicts false alarms: the noisy rules here."""
        return [RuleFeedback(**r) for r in service.rule_feedback(need_db())]

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
    def approve(action_id: uuid.UUID, who: Annotated[str, Depends(actor)]) -> ActionResult:
        if who == "policy" and service.action_kind(need_db(), action_id) == "MAIL_QUARANTINE":
            # a wrong message move costs more than a wrong file move: always your own click
            raise HTTPException(
                status.HTTP_409_CONFLICT, "an email is moved only when you approve it yourself"
            )
        return apply(action_id, Event.APPROVE, who)

    @router.post("/v1/actions/{action_id}/dismiss")
    def dismiss(action_id: uuid.UUID, who: Annotated[str, Depends(actor)]) -> ActionResult:
        return apply(action_id, Event.DISMISS, who)

    @router.post("/v1/actions/{action_id}/restore")
    def restore(action_id: uuid.UUID, who: Annotated[str, Depends(actor)]) -> ActionResult:
        return apply(action_id, Event.RESTORE, who)

    @router.post("/v1/actions/{action_id}/result", dependencies=[Depends(agent_only)])
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
    def allow_add(body: AllowBody, who: Annotated[str, Depends(actor)]) -> AllowOut:
        service.allow_add(need_db(), body.sha256, who, body.days)
        entry = next(a for a in service.allow_list(need_db()) if a["sha256"] == body.sha256)
        return AllowOut(**entry)

    @router.delete("/v1/allowlist/{sha256}")
    def allow_remove(sha256: str, who: Annotated[str, Depends(actor)]) -> dict[str, bool]:
        if not _SHA.match(sha256):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "not a SHA-256")
        return {"removed": service.allow_remove(need_db(), sha256, who)}

    @router.get("/v1/audit")
    def audit(limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[AuditOut]:
        return [AuditOut(**a) for a in service.list_audit(need_db(), limit)]

    return router
