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
    ref: Mapped[str] = mapped_column(Text)  # locator; a URL here is sensitive (ADR-007)
    created_at: Mapped[CreatedAt]


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(253), unique=True)
    registered_domain: Mapped[str | None] = mapped_column(String(253), index=True)
    first_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ExtractedUrl(Base):
    __tablename__ = "extracted_urls"

    id: Mapped[UuidPk]
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    domain_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("domains.id"), index=True)
    url: Mapped[str] = mapped_column(Text)  # sensitive: never log (ADR-006)
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


class AuditLog(Base):
    """Append-only by convention; DB-level enforcement is a known gap (see limitations)."""

    __tablename__ = "audit_logs"

    id: Mapped[UuidPk]
    at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSON)  # redacted before storing
