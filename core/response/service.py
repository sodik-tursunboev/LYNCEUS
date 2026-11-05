"""Storage for responses (M6). Every state change and its audit row are written in one transaction,
compare-and-set on the old state, so two callers cannot both win and an action is never unaudited.
No path or file name is stored here: only ids, hashes, states and reason codes."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

from sqlalchemy import Engine, and_, delete, func, insert, or_, select, update
from sqlalchemy.engine import Row

from core.db import models as db
from core.response.machine import Event, step

_REASON = re.compile(r"^[a-z0-9_]{1,64}$")
_FINISHED = {Event.APPLIED, Event.FAILED, Event.RESTORED}
_AUDIT = {
    Event.APPROVE: "action.approve", Event.DISMISS: "action.dismiss",
    Event.RESTORE: "action.restore",
    Event.APPLIED: "action.applied", Event.FAILED: "action.failed",
    Event.RESTORED: "action.restored", Event.RESTORE_FAILED: "action.restore_failed",
}  # fmt: skip


class Transition(NamedTuple):
    found: bool
    legal: bool
    changed: bool
    state: str | None


def _known(actor: str) -> str:
    """Only the three real actors reach the audit log; anything else is recorded as the user."""
    return actor if actor in ("user", "policy", "agent") else "user"


def _now() -> datetime:
    return datetime.now(UTC)


def _active(sha256: str, now: datetime) -> Any:
    return and_(
        db.Allow.sha256 == sha256, or_(db.Allow.expires_at.is_(None), db.Allow.expires_at > now)
    )


def allow_listed(engine: Engine, sha256: str) -> bool:
    with engine.connect() as c:
        return c.scalar(select(func.count()).where(_active(sha256, _now()))) == 1


def create_pending(
    engine: Engine, verdict_id: uuid.UUID, file_ref: str, sha256: str
) -> uuid.UUID | None:
    """One action per file instance. None when the exact file is allow-listed; the existing id
    when this file already has an action (the agent may send the same file twice)."""
    with engine.begin() as c:
        have = c.scalar(select(db.Action.id).where(db.Action.file_ref == file_ref))
        if have is not None:
            return have
        if c.scalar(select(func.count()).where(_active(sha256, _now()))) == 1:
            return None
        new = uuid.uuid4()
        c.execute(
            insert(db.Action).values(
                id=new, verdict_id=verdict_id, kind="FILE_QUARANTINE", state="PENDING",
                file_ref=file_ref, sha256=sha256,
            )
        )  # fmt: skip
        c.execute(
            insert(db.AuditLog).values(
                actor="policy", action="action.create", target_type="action", target_id=new,
                detail={"sha12": sha256[:12], "to": "PENDING"},
            )
        )  # fmt: skip
        return new


def transition(
    engine: Engine, action_id: uuid.UUID, event: Event, actor: str, reason: str | None = None
) -> Transition:
    actor = _known(actor)
    if reason is not None and not _REASON.match(reason):
        reason = "invalid_reason"
    for _ in range(3):
        with engine.begin() as c:
            row = c.execute(
                select(db.Action.state, db.Action.sha256).where(db.Action.id == action_id)
            ).one_or_none()
            if row is None:
                return Transition(False, False, False, None)
            s = step(row.state, event)
            if not s.legal or not s.changed:
                return Transition(True, s.legal, False, row.state)
            now = _now()
            values: dict[str, Any] = {"state": s.new_state}
            if event in (Event.APPROVE, Event.DISMISS):
                values |= {
                    "decided_by": actor if actor in ("user", "policy") else "user",
                    "decided_at": now,
                }
            if event in _FINISHED:
                values["finished_at"] = now
            if event in (Event.FAILED, Event.RESTORE_FAILED):
                values["reason"] = reason
            elif event in (Event.APPROVE, Event.APPLIED, Event.RESTORED):
                values["reason"] = None
            done = c.execute(
                update(db.Action)
                .where(db.Action.id == action_id, db.Action.state == row.state)
                .values(**values)
            )
            if done.rowcount != 1:
                continue  # someone else moved it first: look again
            c.execute(
                insert(db.AuditLog).values(
                    actor=actor, action=_AUDIT[event], target_type="action", target_id=action_id,
                    detail={"sha12": row.sha256[:12], "from": row.state, "to": s.new_state,
                            "reason": reason},
                )
            )  # fmt: skip
            return Transition(True, True, True, s.new_state)
    raise RuntimeError("the action kept changing under us")


def _action_dict(r: Row[Any]) -> dict[str, Any]:
    return {
        "id": r.id, "verdict_id": r.verdict_id, "kind": r.kind, "state": r.state,
        "file_ref": r.file_ref, "sha256": r.sha256, "decided_by": r.decided_by,
        "reason": r.reason, "created_at": r.created_at,
        "decided_at": r.decided_at, "finished_at": r.finished_at,
        "verdict_state": r.verdict_state, "risk_score": r.risk_score,
    }  # fmt: skip


def _action_query() -> Any:
    return (
        select(db.Action, db.Verdict.state.label("verdict_state"), db.Verdict.risk_score)
        .join(db.Verdict, db.Verdict.id == db.Action.verdict_id)
        .order_by(db.Action.created_at.desc())
    )


def get_action(engine: Engine, action_id: uuid.UUID) -> dict[str, Any] | None:
    with engine.connect() as c:
        row = c.execute(_action_query().where(db.Action.id == action_id)).one_or_none()
    return _action_dict(row) if row else None


def list_actions(engine: Engine, states: list[str] | None, limit: int) -> list[dict[str, Any]]:
    q = _action_query().limit(limit)
    if states:
        q = q.where(db.Action.state.in_(states))
    with engine.connect() as c:
        return [_action_dict(r) for r in c.execute(q)]


def allow_add(engine: Engine, sha256: str, actor: str, days: int | None) -> datetime | None:
    actor = _known(actor)
    expires = _now() + timedelta(days=days) if days else None
    with engine.begin() as c:
        have = c.scalar(select(db.Allow.id).where(db.Allow.sha256 == sha256))
        if have is None:
            c.execute(
                insert(db.Allow).values(
                    id=uuid.uuid4(), sha256=sha256, created_by=actor, expires_at=expires
                )
            )
        else:
            c.execute(update(db.Allow).where(db.Allow.id == have).values(expires_at=expires))
        c.execute(
            insert(db.AuditLog).values(
                actor=actor, action="allowlist.add", target_type="file",
                detail={"sha12": sha256[:12], "days": days},
            )
        )  # fmt: skip
    return expires


def allow_remove(engine: Engine, sha256: str, actor: str) -> bool:
    actor = _known(actor)
    with engine.begin() as c:
        gone = c.execute(delete(db.Allow).where(db.Allow.sha256 == sha256)).rowcount
        if gone:
            c.execute(
                insert(db.AuditLog).values(
                    actor=actor, action="allowlist.remove", target_type="file",
                    detail={"sha12": sha256[:12]},
                )
            )  # fmt: skip
    return bool(gone)


def allow_list(engine: Engine) -> list[dict[str, Any]]:
    now = _now()
    with engine.connect() as c:
        rows = c.execute(
            select(db.Allow).where(or_(db.Allow.expires_at.is_(None), db.Allow.expires_at > now))
            .order_by(db.Allow.created_at.desc())
        )  # fmt: skip
        return [
            {"sha256": r.sha256, "created_by": r.created_by, "created_at": r.created_at,
             "expires_at": r.expires_at}
            for r in rows
        ]  # fmt: skip


def list_events(
    engine: Engine, state: str | None, limit: int, verdict_id: uuid.UUID | None = None
) -> list[dict[str, Any]]:
    q = (
        select(
            db.Verdict.id, db.Verdict.state, db.Verdict.risk_score, db.Verdict.created_at,
            db.Verdict.recommended_response, db.Verdict.applied_response, db.Verdict.explanation,
            db.Artifact.kind, db.Artifact.host, db.Event.source,
        )
        .join(db.Artifact, db.Artifact.id == db.Verdict.artifact_id)
        .join(db.Event, db.Event.id == db.Artifact.event_id)
        .order_by(db.Verdict.created_at.desc())
        .limit(limit)
    )  # fmt: skip
    if state:
        q = q.where(db.Verdict.state == state)
    if verdict_id is not None:
        q = q.where(db.Verdict.id == verdict_id)
    with engine.connect() as c:
        rows = list(c.execute(q))
        ids = [r.id for r in rows]
        rules: dict[uuid.UUID, list[str]] = {}
        actions: dict[uuid.UUID, tuple[uuid.UUID, str]] = {}
        if ids:
            for d in c.execute(
                select(db.Detection.verdict_id, db.Detection.rule_id).where(
                    db.Detection.verdict_id.in_(ids)
                )
            ):
                rules.setdefault(d.verdict_id, []).append(d.rule_id)
            for a in c.execute(
                select(db.Action.verdict_id, db.Action.id, db.Action.state).where(
                    db.Action.verdict_id.in_(ids)
                )
            ):
                actions[a.verdict_id] = (a.id, a.state)
    return [
        {
            "id": r.id, "kind": r.kind, "host": r.host, "source": r.source, "state": r.state,
            "risk_score": r.risk_score, "created_at": r.created_at,
            "recommended": r.recommended_response, "applied": r.applied_response,
            "explanation": r.explanation, "rules": sorted(set(rules.get(r.id, []))),
            "action_id": actions[r.id][0] if r.id in actions else None,
            "action_state": actions[r.id][1] if r.id in actions else None,
        }
        for r in rows
    ]  # fmt: skip


def event_detail(engine: Engine, verdict_id: uuid.UUID) -> dict[str, Any] | None:
    found = list_events(engine, None, 1, verdict_id)
    if not found:
        return None
    with engine.connect() as c:
        signals = [
            {"rule_id": s.rule_id, "category": s.category, "weight": s.weight,
             "description": s.description, "attack": s.attack}
            for s in c.execute(select(db.Detection).where(db.Detection.verdict_id == verdict_id))
        ]  # fmt: skip
        evidence = [
            {"kind": e.kind, "summary": e.summary, "sha256": e.sha256}
            for e in c.execute(select(db.Evidence).where(db.Evidence.verdict_id == verdict_id))
        ]  # fmt: skip
        providers = [
            {"provider": p.provider, "status": p.status, "state": p.state,
             "queried_at": p.queried_at, "provenance": p.provenance}
            for p in c.execute(
                select(db.ProviderResult)
                .join(db.Verdict, db.Verdict.artifact_id == db.ProviderResult.artifact_id)
                .where(db.Verdict.id == verdict_id)
            )
        ]  # fmt: skip
    return found[0] | {"signals": signals, "evidence": evidence, "providers": providers}


def list_audit(engine: Engine, limit: int) -> list[dict[str, Any]]:
    with engine.connect() as c:
        return [
            {"id": r.id, "at": r.at, "actor": r.actor, "action": r.action,
             "target_type": r.target_type,
             "target_id": r.target_id, "detail": r.detail}
            for r in c.execute(select(db.AuditLog).order_by(db.AuditLog.at.desc()).limit(limit))
        ]  # fmt: skip
