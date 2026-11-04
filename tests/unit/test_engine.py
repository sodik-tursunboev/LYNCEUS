from collections.abc import Sequence
from typing import Any

import pytest

from core.contracts import ResponseAction
from core.contracts import VerdictState as V
from core.detection import engine
from core.detection.engine import analyze_url
from core.urls.parse import MAX_URL_LEN


def strip(obj: Any) -> Any:
    """Drop ids and timestamps: everything else must be identical between runs."""
    data = obj.model_dump(mode="json")
    v = data["verdict"]
    v.pop("id"), v.pop("artifact_id"), v.pop("created_at"), v.pop("evidence_ids")
    for s in v["signals"]:
        s.pop("evidence_ids")
    for e in data["evidence"]:
        e.pop("id")
    return data


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal.com@secure-check.test/login.php",
        "https://аllegro.test/konto",
        "http://0xcb007105/",
        "https://www.paypal.com/signin",
        "https://example.test/",
    ],
)
def test_same_input_same_versions_same_result(url: str) -> None:
    assert strip(analyze_url(url)) == strip(analyze_url(url))


def test_every_verdict_names_both_versions() -> None:
    v = analyze_url("https://example.test/").verdict
    assert v.engine_version == engine.ENGINE_VERSION and "+" in v.ruleset_version


def test_no_signals_is_unknown_and_says_it_is_not_safety() -> None:
    v = analyze_url("https://example.test/page").verdict
    assert (v.state, v.risk_score) == (V.UNKNOWN, None)
    assert "not evidence of safety" in v.explanation
    assert v.applied_response is ResponseAction.NONE


def test_official_domain_is_benign_high() -> None:
    v = analyze_url("https://www.paypal.com/signin").verdict
    assert (v.state, v.risk_score) == (V.BENIGN, 0)


@pytest.mark.parametrize(
    "url",
    [
        "https://sites.google.com/view/anything",  # official domain, anyone can publish
        "https://someone.github.io/paypal-login",  # shared hosting (PSL private section)
        "ftp://www.paypal.com/",  # not a web scheme
    ],
)
def test_shared_or_non_web_hosts_are_never_allowlisted(url: str) -> None:
    assert analyze_url(url).verdict.state is not V.BENIGN


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "EMPTY"),
        ("http://ex ample.test/", "UNPARSEABLE"),
        ("x" * (MAX_URL_LEN + 1), "TOO_LONG"),
    ],
)
def test_unparseable_input_is_unknown_with_the_reason(raw: str, reason: str) -> None:
    a = analyze_url(raw)
    assert a.url is None and a.evidence == ()
    assert a.verdict.state is V.UNKNOWN and reason in a.verdict.explanation


def test_a_crashing_rule_gives_error_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "_rules", boom)
    v = analyze_url("https://example.test/").verdict
    assert (v.state, v.risk_score) == (V.ERROR, None)


def test_signals_carry_evidence_and_attack_tags() -> None:
    a = analyze_url("https://paypal.com@secure-check.test/")
    assert a.verdict.state in (V.SUSPICIOUS, V.MALICIOUS)
    ids = {e.id for e in a.evidence}
    assert ids == set(a.verdict.evidence_ids) and ids
    for s in a.verdict.signals:
        assert s.attack and set(s.evidence_ids) <= ids


def test_signals_are_in_a_stable_order() -> None:
    names: Sequence[str] = [
        s.rule_id for s in analyze_url("https://paypal.com@аllegro.test/").verdict.signals
    ]
    assert list(names) == sorted(names) and len(names) >= 2


def test_summaries_do_not_leak_the_query() -> None:
    a = analyze_url("https://paypal.com@evil.test/?email=jane%40example.test&tok=SECRETVALUE")
    assert "SECRETVALUE" not in a.model_dump_json(exclude={"url"})
    assert all("jane" not in e.summary for e in a.evidence)
