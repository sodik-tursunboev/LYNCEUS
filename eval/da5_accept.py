"""DA5 acceptance for 1c, 1d and 1e (docs/milestones/DA5.md): reads the reports in docs/eval and
says, criterion by criterion, whether it holds. Prints DA5 ACCEPTANCE MET only if every one does.

    python -m eval.da5_accept [--docs docs/eval] [--learned rules/learned]

The budgets were fixed before any change (GATES-DA5.md) and are pinned here, never read from a
baseline run of the current code: the three changes together may lose at most 85 of the 15,132
addresses E1's test split flagged before DA5 (0.56%, DA1's own figure for the ranked tier); the D1
test half keeps 65 of 118 live phishing pages caught and at most 1 of 186 legitimate pages flagged;
your browsing stays at 0 flagged; the deep-link flags do not rise above today's 19 (dev) and 20
(test) and the dev half falls to 16 or fewer; the long tail (drawn from Tranco, so partly circular)
falls to 50 or fewer of 3,000. A refitted learned model (1e) may be shipped only if it keeps the
browsing at 0, adds at most 0.3 points on the long tail, catches no fewer fresh test addresses and
loses no E1 test phishing; otherwise the shipped model must still be in rules/learned.
"""

import argparse
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

E1_BEFORE = {
    "E1 test: phiusiil phish": 11347,
    "E1 test: phishtank phish": 3720,
    "E1 test: openphish phish": 65,
}
LOSS_BUDGET = 85
D1_PHISH_KEPT = 65  # of 118; DA1 recorded 66
D1_LEGIT_FLAGGED_MAX = 1  # of 186
DEEP_DEV_BEFORE, DEEP_TEST_BEFORE, DEEP_DEV_AFTER_MAX = 19, 20, 16
TAIL = "long tail, 3,000 home pages (Tranco 100,001 to 1M)"
TAIL_MAX = 50
BROWSING = "your browsing (all)"
SHIPPED_MODEL = "domain-lr-2"

Result = tuple[str, bool, str]


def _k(rows: Mapping[str, Any], cfg: str, name: str) -> int:
    return int(rows[cfg][name]["flagged"]["k"])


def check(
    rules: Mapping[str, Any],
    d1: Mapping[str, Any],
    refit: Mapping[str, Any] | None,
    shipped_version: str,
) -> list[Result]:
    rows = rules["rows"]
    out: list[Result] = []
    for name, before in E1_BEFORE.items():
        c = _k(rows, "C", name)
        out.append((f"baseline reproduces: {name}", c == before, f"{c} against {before} recorded"))
    lost = sum(_k(rows, "C", n) - _k(rows, "E", n) for n in E1_BEFORE)
    total = sum(E1_BEFORE.values())
    out.append((
        f"E1 test: at most {LOSS_BUDGET} of {total:,} flagged phishing addresses lost",
        lost <= LOSS_BUDGET, f"{lost} lost ({100 * lost / total:.2f}%)",
    ))  # fmt: skip
    b = _k(rows, "E", BROWSING)
    out.append(
        ("your browsing: 0 flagged", b == 0, f"{b} of {rows['E'][BROWSING]['flagged']['n']}")
    )
    phish, legit = d1["test"]["phish"]["with_page_alive"], d1["test"]["legit"]["with_page_alive"]
    out.append((
        f"D1 test half: live phishing caught at {D1_PHISH_KEPT} of 118 or better",
        phish["k"] >= D1_PHISH_KEPT and phish["n"] == 118, f"{phish['k']} of {phish['n']}",
    ))  # fmt: skip
    out.append((
        f"D1 test half: legitimate flagged at most {D1_LEGIT_FLAGGED_MAX}",
        legit["k"] <= D1_LEGIT_FLAGGED_MAX, f"{legit['k']} of {legit['n']}",
    ))  # fmt: skip
    dev, test = _k(rows, "E", "deep links, dev half"), _k(rows, "E", "deep links, test half")
    out.append((
        f"deep links: flags not above today's ({DEEP_DEV_BEFORE} dev, {DEEP_TEST_BEFORE} test)",
        dev <= DEEP_DEV_BEFORE and test <= DEEP_TEST_BEFORE, f"{dev} dev, {test} test",
    ))  # fmt: skip
    out.append((
        f"deep links: dev flags fall to {DEEP_DEV_AFTER_MAX} or fewer",
        dev <= DEEP_DEV_AFTER_MAX, f"{dev} of {rows['E']['deep links, dev half']['flagged']['n']}",
    ))  # fmt: skip
    tail = _k(rows, "E", TAIL)
    out.append((
        f"long tail (drawn from Tranco, partly circular): {TAIL_MAX} or fewer of 3,000",
        tail <= TAIL_MAX, f"{tail} (was {_k(rows, 'C', TAIL)})",
    ))  # fmt: skip
    if refit is not None:
        s, c = refit["rows"]["shipped"], refit["rows"]["candidate"]
        fresh = "fresh feeds, phishing on the fresh TEST part"
        e1p = [n for n in s if n.startswith("E1 test: ") and n.endswith(" phish")]
        wins = {
            "browsing 0 flagged": c[BROWSING]["k"] == 0,
            "long tail adds at most 0.3 points": c[TAIL]["rate"] - s[TAIL]["rate"] <= 0.003,
            "fresh test phishing: no fewer caught": c[fresh]["k"] >= s[fresh]["k"],
            "E1 test phishing: none lost": sum(c[n]["k"] for n in e1p)
            >= sum(s[n]["k"] for n in e1p),
        }
        ok = all(wins.values())
        adopted = shipped_version != SHIPPED_MODEL
        out.append((
            "1e: a refitted model is shipped only inside its criteria",
            ok or not adopted,
            f"{'adopted' if adopted else 'not adopted'}; criteria "
            + ", ".join(f"{k}: {'yes' if v else 'NO'}" for k, v in wins.items()),
        ))  # fmt: skip
    return out


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.da5_accept", description=__doc__)
    ap.add_argument("--docs", type=Path, default=Path("docs/eval"))
    ap.add_argument("--learned", type=Path, default=Path("rules/learned"))
    args = ap.parse_args(list(argv) if argv is not None else None)

    def load(name: str) -> Any:
        return json.loads((args.docs / name).read_text(encoding="utf-8"))

    refit = load("refit.json") if (args.docs / "refit.json").exists() else None
    version = str(json.loads((args.learned / "url_host.json").read_text("utf-8"))["version"])
    results = check(load("da5-rules.json"), load("detonate-da5.json"), refit, version.split("+")[0])
    for what, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {what}: {detail}")
    failed = [what for what, ok, _ in results if not ok]
    print(f"DA5 ACCEPTANCE FAILED: {len(failed)} of {len(results)}" if failed
          else "DA5 ACCEPTANCE MET")  # fmt: skip
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
