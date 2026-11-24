"""SQLAlchemy 2 schema (ADR-006). Portable types only, so the same migration runs on PostgreSQL
(production) and SQLite (fast schema tests).

Sensitive evidence bytes live only in `evidence_payloads` (ciphertext + key id, ADR-007); every
other table holds metadata, hashes and references. CHECK constraints repeat the contract
invariants so a buggy writer cannot store e.g. an UNKNOWN verdict with a risk score of 0.
"""

import uuid
from datetime import datetime
from typing import Annotated

from sqlalchemy import (
    DDL,
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from core.contracts import Confidence, ProviderStatus, ResponseAction, VerdictState

NAMING = {  # deterministic constraint names: needed for clean downgrades and drift checks
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map = {datetime: DateTime(timezone=True)}


UuidPk = Annotated[uuid.UUID, mapped_column(primary_key=True, default=uuid.uuid4)]
CreatedAt = Annotated[datetime, mapped_column(server_default=func.now())]


def _in(col: str, values: type[VerdictState] | type[Confidence] | type[ResponseAction]) -> str:
    return f"{col} IN ({', '.join(repr(v.value) for v in values)})"


_OPINIONS = ", ".join(repr(s.value) for s in VerdictState if s is not VerdictState.ERROR)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[UuidPk]
    source: Mapped[str] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(index=True)
    created_at: Mapped[CreatedAt]


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[UuidPk]
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    ref: Mapped[str] = mapped_column(Text)  # "sha256:<hash>" in M1: no URL text before ADR-007
    host: Mapped[str | None] = mapped_column(Text)  # sealed with DPAPI (ADR-007, core/db/hosts.py)
    host_tag: Mapped[str | None] = mapped_column(String(64), index=True)  # keyed hash, for lookups
    created_at: Mapped[CreatedAt]


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(
        String(253), unique=True
    )  # the keyed hash of the host (H1 A8)
    registered_domain: Mapped[str | None] = mapped_column(String(253), index=True)  # keyed hash too
    sealed_name: Mapped[str | None] = mapped_column(Text)  # the host itself, sealed with DPAPI
    first_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ExtractedUrl(Base):
    __tablename__ = "extracted_urls"

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    domain_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("domains.id"), index=True)
    url: Mapped[str | None] = mapped_column(Text)  # always NULL until ADR-007 is signed off
    url_sha256: Mapped[str] = mapped_column(String(64), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[CreatedAt]


class ProviderResult(Base):
    __tablename__ = "provider_results"
    __table_args__ = (
        CheckConstraint("(status = 'OK') = (state IS NOT NULL)", name="opinion_iff_ok"),
        CheckConstraint(f"state IS NULL OR state IN ({_OPINIONS})", name="state_valid"),
        CheckConstraint(
            f"status IN ({', '.join(repr(s.value) for s in ProviderStatus)})", name="status_valid"
        ),
    )

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16))
    state: Mapped[str | None] = mapped_column(String(16))
    queried_at: Mapped[datetime] = mapped_column(index=True)
    latency_ms: Mapped[int] = mapped_column(Integer)
    provenance: Mapped[str] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text)


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = (
        CheckConstraint(_in("state", VerdictState), name="state_valid"),
        CheckConstraint(_in("confidence", Confidence), name="confidence_valid"),
        CheckConstraint(_in("recommended_response", ResponseAction), name="recommended_valid"),
        CheckConstraint(_in("applied_response", ResponseAction), name="applied_valid"),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="score_range"
        ),
        # UNKNOWN/ERROR carry no score (a 0 would read as "safe"); every other state must have one.
        CheckConstraint(
            "(state IN ('UNKNOWN', 'ERROR')) = (risk_score IS NULL)", name="score_iff_scored"
        ),
    )

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(16))
    recommended_response: Mapped[str] = mapped_column(String(16))
    applied_response: Mapped[str] = mapped_column(String(16))
    explanation: Mapped[str] = mapped_column(Text)
    engine_version: Mapped[str] = mapped_column(String(64))
    ruleset_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[CreatedAt] = mapped_column(index=True)


class Detection(Base):
    """A rule firing on an artifact (a contract `Signal`). verdict_id is set once aggregated."""

    __tablename__ = "detections"
    __table_args__ = (CheckConstraint("weight >= 0 AND weight <= 1", name="weight_range"),)

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    verdict_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("verdicts.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64))
    weight: Mapped[float] = mapped_column(Float)
    description: Mapped[str] = mapped_column(Text)
    attack: Mapped[str | None] = mapped_column(String(16))  # e.g. T1566.002
    created_at: Mapped[CreatedAt]


class EvidencePayload(Base):
    """The only table holding sensitive evidence bytes: encrypted, referenced by id (ADR-007)."""

    __tablename__ = "evidence_payloads"

    id: Mapped[UuidPk]
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[CreatedAt]


class Evidence(Base):
    """Evidence metadata only: a redacted summary, a hash and a pointer to the payload."""

    __tablename__ = "evidence"

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    verdict_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("verdicts.id", ondelete="CASCADE"), index=True
    )
    payload_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_payloads.id"), index=True
    )
    kind: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)  # redacted; safe to log and display
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[CreatedAt]


class DetectionEvidence(Base):
    """Which evidence backs which detection (a contract `Signal.evidence_ids`)."""

    __tablename__ = "detection_evidence"

    detection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class AuditLog(Base):
    """Append-only, enforced by the database: a trigger refuses UPDATE, DELETE and TRUNCATE
    (migration 0004, and APPEND_ONLY below for tables made by `create_all`)."""

    __tablename__ = "audit_logs"

    id: Mapped[UuidPk]
    at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSON)  # redacted before storing


# H1 A2: the same triggers as migration 0004, so a table made by `create_all` is append-only too
APPEND_ONLY = {
    "postgresql": [
        "CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$",
        "CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()",
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only()",
    ],
    "sqlite": [
        "CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
        "CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    ],
}
for _dialect, _statements in APPEND_ONLY.items():
    for _statement in _statements:
        event.listen(
            AuditLog.__table__,
            "after_create",
            DDL(_statement).execute_if(dialect=_dialect),  # type: ignore[no-untyped-call]
        )


ACTION_KINDS = ("FILE_QUARANTINE", "MAIL_QUARANTINE")
ACTION_STATES = (
    "PENDING", "APPROVED", "APPLIED", "DISMISSED", "FAILED", "RESTORE_REQUESTED", "RESTORED",
)  # fmt: skip


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(repr(v) for v in values)


class Action(Base):
    """A response to a verdict (M6, ADR-018): what it proposes, what was decided, what happened.

    Holds ids, states and reason codes only: never a path or a file name (those stay with the agent,
    in its quarantine folder). One row follows a file from PENDING through APPLIED to RESTORED.

    For email (M6b, kind MAIL_QUARANTINE) it also holds the provider and the provider's own opaque
    message id (`mail_ref`), which is needed to find the message again: never returned by the API,
    never logged, cleared when the message is restored. No address, subject or body, ever.
    """

    __tablename__ = "actions"
    __table_args__ = (
        CheckConstraint(f"kind IN ({_quoted(ACTION_KINDS)})", name="kind_valid"),
        CheckConstraint(f"state IN ({_quoted(ACTION_STATES)})", name="state_valid"),
        CheckConstraint("decided_by IS NULL OR decided_by IN ('user', 'policy')", name="decider"),
        CheckConstraint(
            "(kind = 'FILE_QUARANTINE' AND provider IS NULL AND mail_ref IS NULL) "
            "OR (kind = 'MAIL_QUARANTINE' AND provider IS NOT NULL "
            "AND provider IN ('gmail', 'outlook'))",  # NULL would otherwise pass a CHECK
            name="provider_valid",
        ),
    )

    id: Mapped[UuidPk]
    verdict_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verdicts.id", ondelete="RESTRICT"), index=True
    )
    kind: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(24), index=True)
    file_ref: Mapped[str] = mapped_column(String(32), unique=True)  # the agent's opaque file id
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    decided_by: Mapped[str | None] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[CreatedAt]
    decided_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    provider: Mapped[str | None] = mapped_column(String(16))  # gmail or outlook (email only)
    mail_ref: Mapped[str | None] = mapped_column(
        String(512)
    )  # the provider's message id (email only)


FEEDBACK_LABELS = ("false_alarm", "missed", "correct")


class Feedback(Base):
    """What the person said about one verdict (H1 B3): a false alarm, a missed phishing, or right.
    One row per verdict, the latest answer; every answer is also in the audit log. With the rules
    that fired (`detections`), it says which rules are noisy on this machine."""

    __tablename__ = "feedback"
    __table_args__ = (
        CheckConstraint(f"label IN ({_quoted(FEEDBACK_LABELS)})", name="label_valid"),
        CheckConstraint("given_by IN ('user')", name="given_by_valid"),
    )

    verdict_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verdicts.id", ondelete="CASCADE"), primary_key=True
    )
    label: Mapped[str] = mapped_column(String(16), index=True)
    given_by: Mapped[str] = mapped_column(String(16))
    given_at: Mapped[CreatedAt]


class Allow(Base):
    """ "Do not propose responses for this exact file again" (by SHA-256). Visible and removable."""

    __tablename__ = "allowlist"

    id: Mapped[UuidPk]
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[CreatedAt]
    expires_at: Mapped[datetime | None]


RETRO_KINDS = ("url", "host")


class RetroAlert(Base):
    """DA5 re-check: a link stored earlier was listed by a threat feed afterwards (core/retro).

    One row per reference and feed, so a rerun adds nothing. `ref` is `sha256:<url hash>` (the exact
    address) or `host:<keyed host hash>` (another address on a listed host); never a URL or a host
    name. The verdict it points at is the one the link got when first seen: it is never edited."""

    __tablename__ = "retro_alerts"
    __table_args__ = (
        UniqueConstraint("ref", "feed"),
        CheckConstraint(f"kind IN ({_quoted(RETRO_KINDS)})", name="kind_valid"),
    )

    id: Mapped[UuidPk]
    ref: Mapped[str] = mapped_column(String(80))
    feed: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(8))
    verdict_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verdicts.id", ondelete="CASCADE"), index=True
    )
    first_seen_at: Mapped[datetime]
    listed_at: Mapped[datetime]
    created_at: Mapped[CreatedAt]
