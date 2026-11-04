"""Wire contracts (pydantic v2): data and invariants only, no I/O.

JSON Schemas are exported to docs/schemas/ with `python -m core.contracts`.
Provisional until docs/SPEC.md is supplied; see ADR-006.
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class VerdictState(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"  # not enough information; never "safe"
    ERROR = "ERROR"  # analysis failed; never "safe"


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ResponseAction(StrEnum):
    """Never includes deletion: responses are reversible (CLAUDE.md rule 7)."""

    NONE = "NONE"
    WARN = "WARN"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class ProviderStatus(StrEnum):
    OK = "OK"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"  # circuit breaker open


class ArtifactKind(StrEnum):
    URL = "URL"
    EMAIL = "EMAIL"
    FILE = "FILE"


class EventSource(StrEnum):
    BROWSER = "BROWSER"
    AGENT = "AGENT"
    EMAIL = "EMAIL"
    API = "API"
    CORPUS = "CORPUS"


REF_MAX_LEN = 8192
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
AttackId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]  # e.g. T1566.002


def _now() -> datetime:
    return datetime.now(UTC)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Artifact(_Model):
    """A thing to analyse. Holds a hash and a locator, never raw email/file content."""

    id: UUID = Field(default_factory=uuid4)
    kind: ArtifactKind
    sha256: Sha256
    # Sensitive for URLs: never log. Same cap as the URL parser (MAX_URL_LEN), checked by a test.
    ref: Annotated[str, Field(min_length=1, max_length=REF_MAX_LEN)]


class Event(_Model):
    id: UUID = Field(default_factory=uuid4)
    source: EventSource
    observed_at: AwareDatetime = Field(default_factory=_now)
    artifacts: Annotated[list[Artifact], Field(min_length=1)]


class Evidence(_Model):
    id: UUID = Field(default_factory=uuid4)
    kind: Annotated[str, Field(min_length=1)]
    summary: Annotated[str, Field(min_length=1)]  # redacted; safe to log and display
    sha256: Sha256 | None = None
    payload_ref: UUID | None = None  # sensitive payload lives apart, encrypted (ADR-007)


class Signal(_Model):
    rule_id: Annotated[str, Field(min_length=1)]
    category: Annotated[str, Field(min_length=1)]
    weight: Annotated[float, Field(ge=0.0, le=1.0)]
    description: Annotated[str, Field(min_length=1)]
    evidence_ids: list[UUID] = Field(default_factory=list)
    attack: AttackId | None = None


class ProviderResult(_Model):
    provider: Annotated[str, Field(min_length=1)]
    status: ProviderStatus
    state: VerdictState | None = None  # the provider's opinion; only when status is OK
    queried_at: AwareDatetime
    latency_ms: Annotated[int, Field(ge=0)]
    provenance: Annotated[str, Field(min_length=1)]  # which feed/version answered
    detail: str | None = None

    @model_validator(mode="after")
    def _opinion_only_when_ok(self) -> Self:
        if self.status is ProviderStatus.OK:
            if self.state is None or self.state is VerdictState.ERROR:
                raise ValueError("an OK provider result needs a state other than ERROR")
        elif self.state is not None:
            raise ValueError(f"a {self.status} result must not carry a verdict state")
        return self


class Verdict(_Model):
    id: UUID = Field(default_factory=uuid4)
    artifact_id: UUID
    state: VerdictState
    # None exactly when state is UNKNOWN/ERROR: a 0 would read as "safe".
    risk_score: Annotated[int, Field(ge=0, le=100)] | None
    confidence: Confidence
    signals: list[Signal]
    evidence_ids: list[UUID]
    provider_results: list[ProviderResult]
    recommended_response: ResponseAction
    applied_response: ResponseAction  # NONE until a response has actually run
    explanation: Annotated[str, Field(min_length=1)]
    engine_version: Annotated[str, Field(min_length=1)]
    ruleset_version: Annotated[str, Field(min_length=1)]  # semver + hash of the rule data
    created_at: AwareDatetime = Field(default_factory=_now)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        unscored = self.state in (VerdictState.UNKNOWN, VerdictState.ERROR)
        if unscored and self.risk_score is not None:
            raise ValueError(f"{self.state} must not carry a risk score")
        if not unscored and self.risk_score is None:
            raise ValueError(f"{self.state} needs a risk score")
        known = set(self.evidence_ids)
        for s in self.signals:
            if not set(s.evidence_ids) <= known:
                raise ValueError(f"signal {s.rule_id} cites evidence not listed on the verdict")
        return self


_SEVERITY = {
    VerdictState.MALICIOUS: 3,
    VerdictState.SUSPICIOUS: 2,
    VerdictState.UNKNOWN: 1,
    VerdictState.BENIGN: 0,
}


def resolve_state(results: Sequence[ProviderResult]) -> VerdictState:
    """Provider opinions -> one state. Conservative placeholder; M3 replaces it with correlation.

    A failed provider is never evidence of safety: BENIGN needs every queried provider to say
    BENIGN. No answers at all is UNKNOWN; only failures is ERROR.
    """
    if not results:
        return VerdictState.UNKNOWN
    answered = [r.state for r in results if r.status is ProviderStatus.OK and r.state]
    if not answered:
        return VerdictState.ERROR
    worst = max(answered, key=_SEVERITY.__getitem__)
    if worst is VerdictState.BENIGN and len(answered) < len(results):
        return VerdictState.UNKNOWN
    return worst


MODELS: tuple[type[BaseModel], ...] = (Event, Artifact, Signal, Evidence, ProviderResult, Verdict)


def export_schemas(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for m in MODELS:
        p = out / f"{m.__name__}.json"
        text = json.dumps(m.model_json_schema(), indent=2, sort_keys=True) + "\n"
        p.write_text(text, encoding="utf-8", newline="\n")
        paths.append(p)
    return paths


if __name__ == "__main__":
    for path in export_schemas(Path("docs/schemas")):
        print(path)
