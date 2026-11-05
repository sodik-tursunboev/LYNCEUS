"""Correlation: how provider answers and local rules combine into one verdict (decision D3).

Golden cases for each combination, plus the property that matters most: a provider that failed,
timed out, was paused or said nothing never changes the score and is never read as safe."""

from datetime import UTC, datetime
from typing import Any

import pytest

from core.contracts import (
    Confidence,
    ProviderResult,
    ProviderStatus,
    ResponseAction,
    VerdictState,
)
from core.detection.engine import UrlAnalysis, analyze_url
from core.intel.base import IntelOutcome, IntelResult
from core.risk.correlate import correlate, provider_note
from rules.intel.data import scoring

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
CLEAN = "https://www.example.com/page"  # no rule fires: UNKNOWN locally
USERINFO = "https://paypal.com@secure-check.test/login.php"  # strong local signals
OFFICIAL = "https://www.paypal.com/signin"  # allowlisted: BENIGN locally


def result(
    provider: str,
    state: VerdictState | None = VerdictState.UNKNOWN,
    facts: dict[str, Any] | None = None,
    status: ProviderStatus = ProviderStatus.OK,
    detail: str | None = "d",
) -> IntelResult:
    ok = status is ProviderStatus.OK
    return IntelResult(
        ProviderResult(
            provider=provider,
            status=status,
            state=state if ok else None,
            queried_at=NOW,
            latency_ms=3,
            provenance=f"{provider} feed",
            detail=detail,
        ),
        facts or {},
    )


def listed(feed: str, how: str = "url") -> IntelResult:
    state = VerdictState.MALICIOUS if how == "url" else VerdictState.SUSPICIOUS
    return result(feed, state, {"listed": how, "feed": feed}, detail="this URL is on the list")


def not_listed(feed: str) -> IntelResult:
    return result(feed, VerdictState.UNKNOWN, detail="not on the list: this proves nothing")


def failed(feed: str, status: ProviderStatus) -> IntelResult:
    return result(feed, status=status, detail="boom")


def outcome(*results: IntelResult, skipped: tuple[tuple[str, str], ...] = ()) -> IntelOutcome:
    return IntelOutcome(tuple(results), skipped)


def mix(url: str, *results: IntelResult) -> UrlAnalysis:
    return correlate(analyze_url(url), outcome(*results))


def shape(a: UrlAnalysis) -> tuple[Any, ...]:
    v = a.verdict
    local = [s.rule_id for s in v.signals if not s.rule_id.startswith("intel.")]
    return v.state, v.risk_score, v.confidence, local


# ---- no providers, or nothing found --------------------------------------------------------------


def test_nobody_asked_means_the_local_analysis_comes_back_untouched() -> None:
    local = analyze_url(USERINFO)
    assert correlate(local, outcome()) is local
    assert correlate(local, outcome(skipped=(("vt", "not a public name"),))) is local


def test_a_clean_answer_changes_nothing_and_says_it_proves_nothing() -> None:
    local = analyze_url(CLEAN)
    mixed = correlate(local, outcome(not_listed("phishtank"), not_listed("openphish")))
    assert shape(mixed) == shape(local) and mixed.verdict.state is VerdictState.UNKNOWN
    assert [r.provider for r in mixed.verdict.provider_results] == ["phishtank", "openphish"]
    assert "proves nothing" in mixed.verdict.explanation
    assert mixed.verdict.risk_score is None  # UNKNOWN stays unscored, never a 0 that reads as safe


@pytest.mark.parametrize("url", [CLEAN, USERINFO, OFFICIAL])
@pytest.mark.parametrize(
    "status",
    [s for s in ProviderStatus if s is not ProviderStatus.OK],
)
def test_a_failed_provider_changes_neither_the_state_nor_the_score(
    url: str, status: ProviderStatus
) -> None:
    local = analyze_url(url)
    mixed = correlate(local, outcome(failed("phishtank", status), failed("openphish", status)))
    assert shape(mixed) == shape(local)
    assert mixed.verdict.provider_results[0].status is status
    assert mixed.verdict.provider_results[0].state is None
    assert (
        "did not" in mixed.verdict.explanation and status.value.lower() in mixed.verdict.explanation
    )


def test_all_providers_failing_never_produces_benign_from_a_non_allowlisted_url() -> None:
    mixed = mix(CLEAN, *[failed(n, ProviderStatus.ERROR) for n in ("a", "b", "c")])
    assert mixed.verdict.state is not VerdictState.BENIGN


def test_an_official_domain_stays_benign_because_of_the_allowlist_not_the_providers() -> None:
    assert mix(OFFICIAL, failed("phishtank", ProviderStatus.TIMEOUT)).verdict.state is (
        VerdictState.BENIGN
    )
    assert mix(OFFICIAL, not_listed("phishtank")).verdict.state is VerdictState.BENIGN


# ---- findings ------------------------------------------------------------------------------------


def test_one_provider_listing_the_exact_url_is_suspicious_with_high_confidence() -> None:
    a = mix(CLEAN, listed("phishtank"), not_listed("openphish"))
    v = a.verdict
    assert v.state is VerdictState.SUSPICIOUS and v.risk_score == 85
    assert v.confidence is Confidence.HIGH and v.recommended_response is ResponseAction.WARN
    (sig,) = v.signals
    assert (sig.rule_id, sig.category) == ("intel.phishtank.url", "intel.phishtank")
    assert v.applied_response is ResponseAction.NONE
    assert {e.id for e in a.evidence} == set(v.evidence_ids) and sig.evidence_ids[
        0
    ] in v.evidence_ids
    assert any(e.kind == "intel" for e in a.evidence)


def test_two_independent_providers_listing_the_url_make_it_malicious() -> None:
    v = mix(CLEAN, listed("phishtank"), listed("openphish")).verdict
    assert v.state is VerdictState.MALICIOUS and v.recommended_response is ResponseAction.BLOCK
    assert v.risk_score is not None and v.risk_score >= 90


def test_one_provider_plus_a_strong_local_category_makes_it_malicious() -> None:
    local = analyze_url(USERINFO)
    assert local.verdict.state is VerdictState.SUSPICIOUS  # the local rules alone: WARN
    v = correlate(local, outcome(listed("urlhaus"))).verdict
    assert v.state is VerdictState.MALICIOUS
    assert {s.rule_id for s in local.verdict.signals} <= {s.rule_id for s in v.signals}


def test_a_host_level_listing_alone_is_too_weak_to_call_it() -> None:
    v = mix(CLEAN, listed("phishtank", "host")).verdict
    assert v.state is VerdictState.UNKNOWN and [s.rule_id for s in v.signals] == [
        "intel.phishtank.host"
    ]
    assert v.confidence is Confidence.LOW


def test_a_listing_on_an_official_domain_makes_it_suspicious_not_benign() -> None:
    v = mix(OFFICIAL, listed("phishtank")).verdict
    assert v.state is VerdictState.SUSPICIOUS


def test_the_same_provider_twice_cannot_add_up_to_certainty() -> None:
    once = mix(CLEAN, listed("phishtank")).verdict.risk_score
    twice = mix(CLEAN, listed("phishtank"), listed("phishtank", "host")).verdict.risk_score
    assert once is not None and twice is not None and twice <= 90  # capped inside its category


def test_a_failing_provider_next_to_a_finding_does_not_weaken_it() -> None:
    plain = mix(CLEAN, listed("phishtank")).verdict
    with_failure = mix(
        CLEAN, listed("phishtank"), failed("openphish", ProviderStatus.TIMEOUT)
    ).verdict
    assert (plain.state, plain.risk_score) == (with_failure.state, with_failure.risk_score)
    assert "openphish timeout" in with_failure.explanation


# ---- facts from other providers (steps 4) --------------------------------------------------------


@pytest.mark.parametrize(
    ("age", "rule"),
    [(3, "week"), (6, "week"), (7, "month"), (29, "month"), (30, "quarter"), (89, "quarter")],
)
def test_domain_age_bands_follow_the_config(age: int, rule: str) -> None:
    age_result = result("rdap", VerdictState.SUSPICIOUS, {"age_days": age})
    (sig,) = mix(CLEAN, age_result).verdict.signals
    assert sig.rule_id == f"intel.domain_age.{rule}" and sig.category == "intel.domain_age"


def test_an_old_domain_adds_nothing() -> None:
    assert (
        mix(CLEAN, result("rdap", VerdictState.UNKNOWN, {"age_days": 4000})).verdict.signals == []
    )


@pytest.mark.parametrize(("n", "rule"), [(1, "few"), (2, "few"), (3, "many"), (40, "many")])
def test_virustotal_detections_follow_the_config(n: int, rule: str) -> None:
    vt = result("virustotal", VerdictState.SUSPICIOUS, {"detections": n})
    (sig,) = mix(CLEAN, vt).verdict.signals
    assert sig.rule_id == f"intel.virustotal.detections_{rule}"


def test_zero_detections_add_nothing() -> None:
    assert (
        mix(CLEAN, result("virustotal", VerdictState.UNKNOWN, {"detections": 0})).verdict.signals
        == []
    )


def test_a_young_domain_with_a_listing_from_a_feed_is_malicious() -> None:
    v = mix(
        CLEAN, listed("phishtank"), result("rdap", VerdictState.SUSPICIOUS, {"age_days": 2})
    ).verdict
    assert v.state is VerdictState.MALICIOUS


def test_a_finding_with_no_configured_weight_is_ignored_not_guessed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    odd = result("newfeed", VerdictState.MALICIOUS, {"listed": "url", "feed": "newfeed"})
    v = mix(CLEAN, odd).verdict
    assert v.signals == [] and v.state is VerdictState.UNKNOWN
    assert "no configured weight" in caplog.text


# ---- bookkeeping ---------------------------------------------------------------------------------


def test_versions_say_intelligence_was_used_only_when_it_was() -> None:
    local = analyze_url(CLEAN)
    mixed = mix(CLEAN, not_listed("phishtank"))
    assert mixed.verdict.engine_version == f"{local.verdict.engine_version}+intel"
    assert mixed.verdict.ruleset_version.startswith(local.verdict.ruleset_version + "+intel.1.0.0+")
    assert local.verdict.engine_version == "1.0.0" and correlate(local, outcome()) is local


def test_the_original_analysis_is_not_modified() -> None:
    local = analyze_url(CLEAN)
    before = local.model_dump_json()
    mix(CLEAN, listed("phishtank"))
    assert local.model_dump_json() == before


def test_unparseable_input_gets_no_intelligence() -> None:
    local = analyze_url("http://ex ample.test/")
    assert correlate(local, outcome(listed("phishtank"))) is local


def test_the_note_names_who_answered_who_did_not_and_who_was_not_asked() -> None:
    note = provider_note(
        outcome(
            listed("phishtank"),
            failed("openphish", ProviderStatus.RATE_LIMITED),
            skipped=(("virustotal", "not a public name"),),
        )
    )
    assert "1 of 2 providers answered" in note and "openphish rate_limited" in note
    assert "not asked: virustotal" in note
    assert provider_note(outcome()) == ""


def test_every_feed_and_fact_maps_to_a_configured_weight_and_cap() -> None:
    from core.intel.feeds import FEEDS

    weights, caps = scoring()["weights"], scoring()["category_caps"]
    for feed in FEEDS:
        assert f"intel.{feed}.url" in weights and f"intel.{feed}.host" in weights
    assert {k.rsplit(".", 1)[0] for k in weights} <= set(caps)
    assert all(0 < w <= 1 for w in weights.values()) and all(0 < c <= 1 for c in caps.values())


def test_facts_attached_to_a_failed_result_are_never_used() -> None:
    liar = result("phishtank", status=ProviderStatus.ERROR)
    liar = IntelResult(liar.result, {"listed": "url", "feed": "phishtank"})  # facts, but no answer
    v = mix(CLEAN, liar).verdict
    assert v.signals == [] and v.state is VerdictState.UNKNOWN


def test_no_category_cap_is_looser_than_a_single_provider_deserves() -> None:
    weights, caps = scoring()["weights"], scoring()["category_caps"]
    for category, cap in caps.items():
        strongest = max(w for k, w in weights.items() if k.rsplit(".", 1)[0] == category)
        assert strongest <= cap <= 0.9, category  # a provider alone never reaches certainty
