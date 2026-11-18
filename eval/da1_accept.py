"""DA1 acceptance (docs/milestones/DA1.md, "Acceptance"): reads the reports in docs/eval and says,
criterion by criterion, whether it holds. Prints DA1 ACCEPTANCE MET only if every one does.

    python -m eval.da1_accept [--docs docs/eval]

Thresholds are the plan's, fixed before the work: the D1 test half's recorded 37.3% live phishing
caught and 7 of 186 legitimate pages flagged; E1's `typosquat` and `brand_in_domain` legitimate hits
must fall while phishing caught does not fall below its old interval; your browsing stays at 0
flagged; the synthetic mail corpus keeps TP 73, FP 0, FN 1.
"""

import argparse
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

D1_PHISH_BEFORE = 0.373  # D1, test half, URL rules + page, alive pages
D1_LEGIT_FLAGGED_BEFORE = 7  # of 186 alive legitimate pages
# E1 test split, phishing flagged by the address engine: the low end of each interval recorded
# before the DA3 rule changes (the DA1 report). Pinned, not read from a baseline run of the
# current code: a regression that hits baseline and final rules alike would otherwise pass.
E1_FLOORS = {"phiusiil phish": 0.3716, "phishtank phish": 0.2571, "openphish phish": 0.6067}
BROWSING = "your browsing (never trained on)"
MAIL_BEFORE = {"tp": 73, "fp": 0, "abstain_pos": 1}

Result = tuple[str, bool, str]


def check(
    d1: Mapping[str, Any],
    rules: Mapping[str, Any],
    learned: Mapping[str, Any],
    mail: Mapping[str, Any],
) -> list[Result]:
    out: list[Result] = []
    phish, legit = d1["test"]["phish"]["with_page_alive"], d1["test"]["legit"]["with_page_alive"]
    out.append((
        "D1 test half: live phishing caught, lower bound above the old 37.3%",
        phish["low"] > D1_PHISH_BEFORE,
        f"{phish['rate']:.3f} (low {phish['low']:.3f}), {phish['k']} of {phish['n']}",
    ))  # fmt: skip
    out.append((
        f"D1 test half: legitimate flagged no more than {D1_LEGIT_FLAGGED_BEFORE}",
        legit["k"] <= D1_LEGIT_FLAGGED_BEFORE, f"{legit['k']} of {legit['n']}",
    ))  # fmt: skip
    rows = rules["rows"]
    for rule in ("typosquat", "brand_in_domain"):
        before = sum(r[rule] for n, r in rows["A"].items() if n.endswith(" legit"))
        after = sum(r[rule] for n, r in rows["C"].items() if n.endswith(" legit"))
        out.append(
            (f"E1 test: legitimate {rule} hits fall", after < before, f"{before} to {after}")
        )
    for name, low in E1_FLOORS.items():
        c = rows["C"][name]["flagged"]
        out.append((
            f"E1 test: {name} caught, not below its old interval",
            c["rate"] >= low, f"{c['rate']:.4f} against low {low:.4f}",
        ))  # fmt: skip
    mine = learned["sets"][BROWSING]["product"]
    out.append(("your browsing: 0 flagged", mine["k"] == 0, f"{mine['k']} of {mine['n']}"))
    c = mail["counts"]
    out.append((
        "mail corpus: no new false alarm, no new miss",
        c["tp"] >= MAIL_BEFORE["tp"] and c["fp"] == MAIL_BEFORE["fp"] and c["fn_benign"] == 0
        and c["abstain_pos"] <= MAIL_BEFORE["abstain_pos"],
        f"TP {c['tp']}, FP {c['fp']}, FN {c['abstain_pos']}",
    ))  # fmt: skip
    return out


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.da1_accept", description=__doc__)
    ap.add_argument("--docs", type=Path, default=Path("docs/eval"))
    args = ap.parse_args(list(argv) if argv is not None else None)

    def load(name: str) -> Any:
        return json.loads((args.docs / name).read_text(encoding="utf-8"))

    results = check(
        load("detonate-da1.json"),
        load("da1-rules.json"),
        load("learned-url.json"),
        load("mail-dev.json"),
    )
    for what, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {what}: {detail}")
    failed = [what for what, ok, _ in results if not ok]
    print(f"DA1 ACCEPTANCE FAILED: {len(failed)} of {len(results)}" if failed
          else "DA1 ACCEPTANCE MET")  # fmt: skip
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
