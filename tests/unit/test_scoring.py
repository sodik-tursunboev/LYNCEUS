from typing import Any

from core.contracts import Confidence, ResponseAction, Signal
from core.contracts import VerdictState as V
from core.risk.scoring import score
from rules.url.data import scoring

CFG: dict[str, Any] = {
    "thresholds": {"suspicious": 45, "malicious": 80, "high_weight": 0.5, "min_categories": 2},
    "category_caps": {"a": 0.8, "b": 0.8, "weak": 0.3},
}


def sig(category: str, weight: float) -> Signal:
    return Signal(rule_id=f"r.{category}", category=category, weight=weight, description="d")


def test_no_signals_is_unknown_never_benign() -> None:
    r = score([], False, CFG)
    assert (r.state, r.risk_score) == (V.UNKNOWN, None)


def test_allowlisted_with_no_signals_is_benign_high() -> None:
    r = score([], True, CFG)
    assert (r.state, r.risk_score, r.confidence) == (V.BENIGN, 0, Confidence.HIGH)


def test_one_strong_category_is_capped_at_suspicious() -> None:
    r = score([sig("a", 0.95), sig("a", 0.9)], False, {**CFG, "category_caps": {"a": 1.0}})
    assert r.risk_score is not None and r.risk_score >= 80
    assert r.state is V.SUSPICIOUS


def test_two_independent_strong_categories_reach_malicious() -> None:
    r = score([sig("a", 0.7), sig("b", 0.7)], False, CFG)
    assert (r.state, r.risk_score) == (V.MALICIOUS, 91)
    assert r.recommended_response is ResponseAction.BLOCK


def test_weak_category_does_not_count_as_independent() -> None:
    r = score([sig("a", 0.8), sig("weak", 0.4)], False, CFG)
    assert r.state is V.SUSPICIOUS and r.recommended_response is ResponseAction.WARN


def test_category_cap_limits_correlated_signals() -> None:
    capped = score([sig("weak", 0.4), sig("weak", 0.41), sig("weak", 0.42)], False, CFG)
    assert capped.state is V.UNKNOWN  # 3 signals of one kind stay at the cap of 30


def test_weak_signals_are_unknown_unless_allowlisted() -> None:
    assert score([sig("x", 0.3)], False, CFG).state is V.UNKNOWN
    r = score([sig("x", 0.3)], True, CFG)
    assert (r.state, r.confidence) == (V.BENIGN, Confidence.MEDIUM)


def test_allowlist_does_not_override_a_strong_finding() -> None:
    assert score([sig("a", 0.7)], True, CFG).state is V.SUSPICIOUS


def test_order_of_signals_does_not_matter() -> None:
    signals = [sig("a", 0.7), sig("b", 0.6), sig("x", 0.3)]
    assert score(signals, False, CFG) == score(signals[::-1], False, CFG)


def test_shipped_config_is_usable() -> None:
    t = scoring()["thresholds"]
    assert 0 < t["suspicious"] < t["malicious"] <= 100
