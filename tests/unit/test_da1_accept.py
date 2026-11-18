"""DA1's acceptance checker: it passes a report set that meets the plan and fails each criterion
that does not (a checker that cannot fail proves nothing)."""

import copy
from typing import Any

from eval.da1_accept import BROWSING, check


def rate(k: int, n: int, low: float) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n, "low": low, "ci": [low, 1.0]}


def legit(typo: int, brand: int, k: int) -> dict[str, Any]:
    return {"typosquat": typo, "brand_in_domain": brand, "flagged": rate(k, 40685, 0.0)}


def phish(typo: int, brand: int, caught: float) -> dict[str, Any]:
    return {"typosquat": typo, "brand_in_domain": brand, "flagged": {"rate": caught}}


GOOD: dict[str, Any] = {
    "d1": {"test": {"phish": {"with_page_alive": rate(66, 118, 0.469)},
                    "legit": {"with_page_alive": rate(1, 186, 0.001)}}},
    "rules": {"rows": {
        "A": {"x legit": legit(20, 79, 56)},
        "C": {
            "x legit": legit(15, 57, 51),
            "phiusiil phish": phish(77, 482, 0.3771),
            "phishtank phish": phish(13, 73, 0.2643),
            "openphish phish": phish(12, 11, 0.7065),
        },
    }},
    "learned": {"sets": {BROWSING: {"product": rate(0, 92, 0.0)}}},
    "mail": {"counts": {"tp": 73, "fp": 0, "fn_benign": 0, "abstain_pos": 1}},
}  # fmt: skip


def run(change: Any = None) -> list[tuple[str, bool]]:
    data = copy.deepcopy(GOOD)
    if change:
        change(data)
    return [(w, ok) for w, ok, _ in check(data["d1"], data["rules"], data["learned"], data["mail"])]


def test_a_report_set_that_meets_the_plan_passes_every_criterion() -> None:
    assert run() and all(ok for _, ok in run())


def failing(change: Any) -> list[str]:
    return [w for w, ok in run(change) if not ok]


def test_each_criterion_fails_when_it_is_not_met() -> None:
    def d1_low(d: Any) -> None:
        d["d1"]["test"]["phish"]["with_page_alive"]["low"] = 0.30

    def d1_legit(d: Any) -> None:
        d["d1"]["test"]["legit"]["with_page_alive"]["k"] = 8

    def typo(d: Any) -> None:
        d["rules"]["rows"]["C"]["x legit"]["typosquat"] = 20

    def brand(d: Any) -> None:
        d["rules"]["rows"]["C"]["x legit"]["brand_in_domain"] = 80

    def caught(d: Any) -> None:
        d["rules"]["rows"]["C"]["phishtank phish"]["flagged"]["rate"] = 0.20

    def browsing(d: Any) -> None:
        d["learned"]["sets"][BROWSING]["product"]["k"] = 1

    def mail_fp(d: Any) -> None:
        d["mail"]["counts"]["fp"] = 1

    def mail_miss(d: Any) -> None:
        d["mail"]["counts"]["abstain_pos"] = 2

    for change, word in [
        (d1_low, "lower bound"), (d1_legit, "legitimate flagged"), (typo, "typosquat"),
        (brand, "brand_in_domain"), (caught, "not below"), (browsing, "browsing"),
        (mail_fp, "mail corpus"), (mail_miss, "mail corpus"),
    ]:  # fmt: skip
        found = failing(change)
        assert len(found) == 1 and word in found[0], (word, found)
