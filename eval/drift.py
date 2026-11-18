# ruff: noqa: E501  (report rows are long literals)
"""DA3: does the learned domain model age? Train on older data only, test on the 2026 feeds.

    python -m eval.drift [--data .data/eval] [--out docs/eval]

Two models, both calibrated the same way as the shipped one (threshold at 0.4% of the calibration
domains' legitimate names) and both tested on the SAME test domains:
  shipped   trained on every E1 source (PhiUSIIL, PhishTank, OpenPhish of 2026-11-10, Tranco, PhiUSIIL legit)
  older     trained on PhiUSIIL (collected 2024) and Tranco only: it has never seen a 2026 feed
The gap on PhishTank and OpenPhish is what a model loses by not being retrained on fresh feeds.
"""

import argparse
import json
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import features
from eval import realurl as e1
from eval.learn_url import parsed, part, prob, train
from eval.metrics import wilson


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.drift", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args(list(argv) if argv is not None else None)
    _ = os.cpu_count()

    hosts: dict[tuple[str, int], tuple[str, set[str], list[int]]] = {}
    labels_of: dict[str, set[int]] = defaultdict(set)
    for s in e1.load(args.data, 50_000):
        if s.source == "edge_history" or e1.split_of(s.url) == "reserve":
            continue
        u = parsed(s.url)
        if u is None or not u.registered_domain:
            continue
        y = 1 if s.label == e1.PHISH else 0
        labels_of[u.registered_domain].add(y)
        key = (u.registered_domain, y)
        if key in hosts:
            hosts[key][1].add(s.source)
        else:
            hosts[key] = (part(u.registered_domain), {s.source}, list(features(u)))
    clash = {h for h, ys in labels_of.items() if len(ys) > 1}
    rows = [(d, y, p, src, f) for (d, y), (p, src, f) in hosts.items() if d not in clash]

    def fit(sources: set[str] | None) -> tuple[float, list[float], float]:
        fit_rows = [
            (f, y)
            for d, y, p, src, f in rows
            if p == "train" and (sources is None or src & sources)
        ]
        bias, w = train(fit_rows, args.epochs)
        calib = sorted(prob(bias, w, f) for d, y, p, src, f in rows if p == "calib" and y == 0)
        return bias, w, max(calib[int(len(calib) * 0.996)], 0.5)

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "models": {},
    }
    for name, sources in (
        ("shipped (all sources)", None),
        ("older (PhiUSIIL and Tranco only)", {"phiusiil", "tranco"}),
    ):
        bias, w, thr = fit(sources)
        out: dict[str, Any] = {"threshold": round(thr, 4)}
        for label, want_y, want_src in (
            ("PhishTank phishing (2026)", 1, "phishtank"), ("OpenPhish phishing (2026)", 1, "openphish"),
            ("PhiUSIIL phishing (2024)", 1, "phiusiil"), ("legitimate (Tranco and PhiUSIIL)", 0, None),
        ):  # fmt: skip
            sel = [
                f
                for d, y, p, src, f in rows
                if p == "test" and y == want_y and (want_src is None or want_src in src)
            ]
            out[label] = _rate(sum(prob(bias, w, f) >= thr for f in sel), len(sel))
        report["models"][name] = out
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "drift.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "drift.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        return (
            "n/a"
            if not r["n"]
            else f"{100 * r['rate']:.1f}% ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}), {r['k']} of {r['n']}"
        )

    names = list(rep["models"])
    sets = [k for k in rep["models"][names[0]] if k != "threshold"]
    lines = [
        "# Does the learned model age? (DA3)", "",
        f"{rep['generated_at']}. Domain-name model only (no URL rules), same test domains for both models, threshold at 0.4% of the calibration domains' legitimate names for each. The older model has never seen a 2026 feed. Intervals are Wilson 95%.", "",
        "| test set | " + " | ".join(f"{n} (threshold {rep['models'][n]['threshold']})" for n in names) + " |",
        "|---|" + "---|" * len(names),
    ]  # fmt: skip
    lines += [
        f"| {s} | " + " | ".join(pct(rep["models"][n][s]) for n in names) + " |" for s in sets
    ]
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
