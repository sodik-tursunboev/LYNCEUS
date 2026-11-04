import itertools
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from core.contracts import (
    MODELS,
    Artifact,
    ArtifactKind,
    Confidence,
    Evidence,
    ProviderResult,
    ProviderStatus,
    ResponseAction,
    Signal,
    Verdict,
    VerdictState,
    export_schemas,
    resolve_state,
)

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
FAILED = [s for s in ProviderStatus if s is not ProviderStatus.OK]


def pr(
    status: ProviderStatus = ProviderStatus.OK, state: VerdictState | None = None
) -> ProviderResult:
    if status is ProviderStatus.OK and state is None:
        state = VerdictState.BENIGN
    return ProviderResult(
        provider="test-feed", status=status, state=state, queried_at=NOW, latency_ms=5,
        provenance="test-feed v1",
    )  # fmt: skip


def verdict_kwargs(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "artifact_id": uuid4(),
        "state": VerdictState.SUSPICIOUS,
        "risk_score": 40,
        "confidence": Confidence.MEDIUM,
        "signals": [],
        "evidence_ids": [],
        "provider_results": [],
        "recommended_response": ResponseAction.WARN,
        "applied_response": ResponseAction.NONE,
        "explanation": "test",
        "engine_version": "test-0",
        "ruleset_version": "test-0",
    }
    return base | over


# ---- UNKNOWN / ERROR are never "safe" ---------------------------------------------------------


def test_five_distinct_states() -> None:
    assert {s.value for s in VerdictState} == {
        "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "ERROR",
    }  # fmt: skip
    assert VerdictState.UNKNOWN != VerdictState.BENIGN
    assert VerdictState.ERROR not in (VerdictState.UNKNOWN, VerdictState.BENIGN)


def test_unknown_string_parses_as_unknown_not_benign() -> None:
    v = Verdict.model_validate(
        json.loads(Verdict(**verdict_kwargs(state="UNKNOWN", risk_score=None)).model_dump_json())
    )
    assert v.state is VerdictState.UNKNOWN


def test_resolve_state_empty_is_unknown() -> None:
    assert resolve_state([]) is VerdictState.UNKNOWN


@pytest.mark.parametrize("status", FAILED)
def test_provider_failure_alone_is_error_never_benign(status: ProviderStatus) -> None:
    assert resolve_state([pr(status)]) is VerdictState.ERROR


def test_benign_needs_every_provider_to_answer_benign() -> None:
    assert resolve_state([pr(state=VerdictState.BENIGN)]) is VerdictState.BENIGN
    assert resolve_state([pr(), pr(ProviderStatus.TIMEOUT)]) is VerdictState.UNKNOWN
    assert resolve_state([pr(), pr(state=VerdictState.UNKNOWN)]) is VerdictState.UNKNOWN


def test_positive_stands_despite_a_failed_provider() -> None:
    results = [pr(state=VerdictState.SUSPICIOUS), pr(ProviderStatus.TIMEOUT)]
    assert resolve_state(results) is VerdictState.SUSPICIOUS
    assert resolve_state([pr(state=VerdictState.MALICIOUS), pr()]) is VerdictState.MALICIOUS


def test_benign_is_never_returned_unless_every_result_says_benign() -> None:
    options = [pr(s) for s in FAILED] + [
        pr(state=s) for s in VerdictState if s is not VerdictState.ERROR
    ]
    for n in (1, 2, 3):
        for combo in itertools.product(options, repeat=n):
            if resolve_state(combo) is VerdictState.BENIGN:
                assert all(
                    r.status is ProviderStatus.OK and r.state is VerdictState.BENIGN for r in combo
                )


@pytest.mark.parametrize("state", [VerdictState.UNKNOWN, VerdictState.ERROR])
def test_unscored_states_reject_a_risk_score(state: VerdictState) -> None:
    with pytest.raises(ValidationError):
        Verdict(**verdict_kwargs(state=state, risk_score=0))  # 0 would read as "safe"
    Verdict(**verdict_kwargs(state=state, risk_score=None))


@pytest.mark.parametrize(
    "state", [VerdictState.BENIGN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS]
)
def test_scored_states_need_a_risk_score(state: VerdictState) -> None:
    with pytest.raises(ValidationError):
        Verdict(**verdict_kwargs(state=state, risk_score=None))


def test_responses_never_delete() -> None:
    assert not [a for a in ResponseAction if "DELETE" in a.value]


# ---- required fields and shape ----------------------------------------------------------------

REQUIRED = [n for n, f in Verdict.model_fields.items() if f.is_required()]


def test_required_field_list_is_what_the_spec_demands() -> None:
    assert set(REQUIRED) >= {
        "state", "risk_score", "confidence", "signals", "evidence_ids", "provider_results",
        "recommended_response", "applied_response", "explanation",
    }  # fmt: skip


@pytest.mark.parametrize("field", REQUIRED)
def test_verdict_requires_field(field: str) -> None:
    kw = verdict_kwargs()
    del kw[field]
    with pytest.raises(ValidationError):
        Verdict(**kw)


def test_naive_datetimes_rejected() -> None:
    with pytest.raises(ValidationError):
        Verdict(**verdict_kwargs(created_at=datetime(2026, 11, 4)))  # noqa: DTZ001


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        Verdict(**verdict_kwargs(surprise=1))


def test_signal_evidence_must_be_listed_on_the_verdict() -> None:
    ev = uuid4()
    sig = Signal(rule_id="r1", category="url", weight=0.5, description="d", evidence_ids=[ev])
    with pytest.raises(ValidationError):
        Verdict(**verdict_kwargs(signals=[sig], evidence_ids=[]))
    Verdict(**verdict_kwargs(signals=[sig], evidence_ids=[ev]))


def test_provider_result_invariants() -> None:
    with pytest.raises(ValidationError):
        pr(ProviderStatus.OK, VerdictState.ERROR)
    for s in FAILED:
        with pytest.raises(ValidationError):
            pr(s, VerdictState.BENIGN)  # a failure cannot carry an opinion
    with pytest.raises(ValidationError):
        ProviderResult(
            provider="p", status=ProviderStatus.OK, state=None, queried_at=NOW, latency_ms=1,
            provenance="x",
        )  # fmt: skip


def test_field_constraints() -> None:
    with pytest.raises(ValidationError):
        Signal(rule_id="r", category="c", weight=1.5, description="d")
    with pytest.raises(ValidationError):
        Signal(rule_id="r", category="c", weight=0.1, description="d", attack="1566")
    Signal(rule_id="r", category="c", weight=0.1, description="d", attack="T1566.002")
    with pytest.raises(ValidationError):
        Artifact(kind=ArtifactKind.URL, sha256="nothex", ref="https://a.test/")
    with pytest.raises(ValidationError):
        Evidence(kind="k", summary="")


# ---- JSON Schema export -----------------------------------------------------------------------


def test_exported_schemas_match_committed_files(tmp_path: Path) -> None:
    committed = Path(__file__).parents[2] / "docs" / "schemas"
    written = export_schemas(tmp_path)
    assert {p.name for p in written} == {f"{m.__name__}.json" for m in MODELS}
    for p in written:
        want = json.loads((committed / p.name).read_text(encoding="utf-8"))
        assert json.loads(p.read_text(encoding="utf-8")) == want, (
            f"{p.name} is stale: run `python -m core.contracts`"
        )
