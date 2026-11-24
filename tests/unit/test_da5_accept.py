"""The DA5 acceptance checker fails each budget when broken, and passes the recorded reports."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from eval import da5_accept as acc

DOCS = Path("docs/eval")


def _good() -> tuple[dict[str, Any], dict[str, Any]]:
    def row(k: int, n: int) -> dict[str, Any]:
        return {"flagged": {"k": k, "n": n}}

    base = {
        "E1 test: phiusiil phish": row(11347, 30090),
        "E1 test: phishtank phish": row(3720, 14075),
        "E1 test: openphish phish": row(65, 92),
        acc.BROWSING: row(0, 97),
        "deep links, dev half": row(19, 757),
        "deep links, test half": row(20, 883),
        acc.TAIL: row(72, 3000),
    }
    after = copy.deepcopy(base)
    after["E1 test: phiusiil phish"] = row(11287, 30090)  # 60 lost, inside the budget of 85
    after["deep links, dev half"] = row(13, 757)
    after["deep links, test half"] = row(10, 883)
    after[acc.TAIL] = row(3, 3000)
    rules = {"rows": {"C": base, "E": after}}
    d1 = {
        "test": {
            "phish": {"with_page_alive": {"k": 66, "n": 118}},
            "legit": {"with_page_alive": {"k": 1, "n": 186}},
        }
    }
    return rules, d1


def _passes(rules: dict[str, Any], d1: dict[str, Any]) -> bool:
    return all(ok for _, ok, _ in acc.check(rules, d1, None, acc.SHIPPED_MODEL))


def test_the_checker_passes_the_recorded_reports() -> None:
    names = ["da5-rules.json", "detonate-da5.json"]
    if not all((DOCS / n).exists() for n in names):
        pytest.skip("the DA5 reports are not on this machine (they need the evaluation data)")
    rules, d1 = (json.loads((DOCS / n).read_text("utf-8")) for n in names)
    failed = [w for w, ok, _ in acc.check(rules, d1, None, acc.SHIPPED_MODEL) if not ok]
    assert not failed, failed


def test_the_checker_passes_a_good_set() -> None:
    assert _passes(*_good())


def test_the_checker_fails_when_the_phishing_loss_budget_is_broken() -> None:
    rules, d1 = _good()
    rules["rows"]["E"]["E1 test: phiusiil phish"]["flagged"]["k"] = 11347 - 86
    assert not _passes(rules, d1)


def test_the_checker_fails_when_browsing_gets_a_flag() -> None:
    rules, d1 = _good()
    rules["rows"]["E"][acc.BROWSING]["flagged"]["k"] = 1
    assert not _passes(rules, d1)


def test_the_checker_fails_when_the_deep_link_flags_rise() -> None:
    rules, d1 = _good()
    rules["rows"]["E"]["deep links, test half"]["flagged"]["k"] = 21
    assert not _passes(rules, d1)


def test_the_checker_fails_when_the_live_pages_lose_a_catch_or_gain_a_false_alarm() -> None:
    rules, d1 = _good()
    d1["test"]["phish"]["with_page_alive"]["k"] = 64
    assert not _passes(rules, d1)
    rules, d1 = _good()
    d1["test"]["legit"]["with_page_alive"]["k"] = 2
    assert not _passes(rules, d1)


def test_a_refitted_model_that_misses_its_criteria_may_not_be_shipped() -> None:
    rules, d1 = _good()
    fresh = "fresh feeds, phishing on the fresh TEST part"
    shipped = {n: {"k": 5, "rate": 0.01} for n in (fresh, acc.TAIL, acc.BROWSING)}
    shipped["E1 test: phishtank phish"] = {"k": 100, "rate": 0.3}
    worse = copy.deepcopy(shipped)
    worse[fresh]["k"] = 4  # one fewer fresh catch: the criterion fails
    refit = {"rows": {"shipped": shipped, "candidate": worse}}
    shipped["E1 test: phishtank phish"]["k"] = 100
    worse[acc.BROWSING]["k"] = 0
    shipped[acc.BROWSING]["k"] = 0
    assert all(
        ok for _, ok, _ in acc.check(rules, d1, refit, acc.SHIPPED_MODEL)
    )  # not adopted: fine
    assert not all(ok for _, ok, _ in acc.check(rules, d1, refit, "domain-lr-3-candidate"))
