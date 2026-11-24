# ruff: noqa: E501  (report rows are long literals)
"""DA4: does the engine hold up on phishing that appeared AFTER it was fitted, and does refitting help?

    python -m eval.fresh [--data .data/eval] [--fresh .data/eval/fresh-2026-11-22] [--out docs/eval]

The feeds in --fresh were downloaded 12 days after the E1 feeds the shipped model was fitted on
(the download itself is a plain copy of the same two public files, recorded in its sources.json).
Phishing there whose registered domain E1 never held (any split) is the nearest thing to tomorrow's
traffic this project can measure offline. Two questions:

1. As the product runs (address rules, the learned model, the popular list), how much of it is
   flagged, against the same engine on E1's test split? A big drop is drift in the field.
2. For the domain-name model alone: fitted on E1's train split, against the same plus the train part
   of the fresh domains, read on the fresh test part and on E1's test split, with the threshold taken
   from E1's calibration legitimate names (0.4%) for both. The fresh domains are split by the same
   domain hash as E1's, so no name is in both a train and a test part.
"""

import argparse
import json
import os
from collections.abc import Iterable, Iterator, Mapping
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import features
from eval import da1_rules
from eval import realurl as e1
from eval.learn_url import parsed, part, prob, train
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def fresh_samples(folder: Path) -> Iterator[e1.Sample]:
    yield from e1.phishtank(folder / "phishtank.json.bz2")
    yield from e1.openphish(folder / "openphish.txt")


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.fresh", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--fresh", type=Path, default=Path(".data/eval/fresh-2026-11-22"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args(list(argv) if argv is not None else None)

    old = [s for s in e1.load(args.data, 50_000) if s.source != "edge_history"]
    known_domains = set()
    for s in old:
        u = parsed(s.url)
        if u is not None and u.registered_domain:
            known_domains.add(u.registered_domain)
    known_urls = {s.url for s in old}
    new: list[e1.Sample] = []
    seen: set[str] = set()
    total = 0
    for s in fresh_samples(args.fresh):
        total += 1
        u = parsed(s.url)
        if u is None or not u.registered_domain or s.url in known_urls:
            continue
        if u.registered_domain in known_domains or s.url in seen:
            continue
        seen.add(s.url)
        new.append(s)

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "fresh_files": [  # the file digests stay in the download's own sources.json
            {k: v for k, v in f.items() if k != "sha256"}
            for f in json.loads((args.fresh / "sources.json").read_text(encoding="utf-8-sig"))
        ],
        "fresh_addresses": total,
        "fresh_new_domains": len(new),
    }

    # 1. the whole address engine, as the product runs it
    init = partial(da1_rules.setup, "C", args.data)
    old_test = [s for s in old if s.label == e1.PHISH and e1.split_of(s.url) == "test"]
    sets = {
        "E1 test split (feeds of 2026-11-10), PhishTank": [
            s for s in old_test if s.source == "phishtank"
        ],
        "E1 test split, OpenPhish": [s for s in old_test if s.source == "openphish"],
        "fresh feeds (2026-11-22), new domains, PhishTank": [
            s for s in new if s.source == "phishtank"
        ],
        "fresh feeds, new domains, OpenPhish": [s for s in new if s.source == "openphish"],
    }
    engine: dict[str, Any] = {}
    for name, sel in sets.items():
        judged = e1.judge(sel, args.workers, init)
        engine[name] = _rate(sum(j[0] in FLAGGED for j in judged), len(sel))
    report["engine"] = engine

    # 2. the domain-name model, refitted with and without the fresh train part
    rows: dict[tuple[str, int], tuple[str, list[int]]] = {}
    labels_of: dict[str, set[int]] = {}
    for s in old:
        if e1.split_of(s.url) == "reserve":
            continue
        u = parsed(s.url)
        if u is None or not u.registered_domain:
            continue
        y = 1 if s.label == e1.PHISH else 0
        labels_of.setdefault(u.registered_domain, set()).add(y)
        rows.setdefault((u.registered_domain, y), (part(u.registered_domain), list(features(u))))
    clash = {d for d, ys in labels_of.items() if len(ys) > 1}
    base = [(p, y, f, d) for (d, y), (p, f) in rows.items() if d not in clash]
    fresh_rows: dict[str, tuple[str, list[int]]] = {}
    for s in new:
        u = parsed(s.url)
        if u is not None and u.registered_domain and u.registered_domain not in clash:
            fresh_rows.setdefault(
                u.registered_domain, (part(u.registered_domain), list(features(u)))
            )

    def fit(extra: bool) -> tuple[float, list[float], float]:
        fit_rows = [(f, y) for p, y, f, _ in base if p == "train"]
        if extra:
            fit_rows += [(f, 1) for p, f in fresh_rows.values() if p == "train"]
        bias, w = train(fit_rows, args.epochs)
        calib = sorted(prob(bias, w, f) for p, y, f, _ in base if p == "calib" and y == 0)
        return bias, w, max(calib[int(len(calib) * 0.996)], 0.5)

    fresh_test = [f for p, f in fresh_rows.values() if p == "test"]
    old_phish_test = [f for p, y, f, _ in base if p == "test" and y == 1]
    old_legit_test = [f for p, y, f, _ in base if p == "test" and y == 0]
    models: dict[str, Any] = {}
    for name, extra in (
        ("fitted on E1 train only", False),
        ("fitted on E1 train and the fresh train part", True),
    ):
        bias, w, thr = fit(extra)
        models[name] = {
            "threshold": round(thr, 4),
            "fresh test domains": _rate(
                sum(prob(bias, w, f) >= thr for f in fresh_test), len(fresh_test)
            ),
            "E1 test phishing": _rate(
                sum(prob(bias, w, f) >= thr for f in old_phish_test), len(old_phish_test)
            ),
            "E1 test legitimate": _rate(
                sum(prob(bias, w, f) >= thr for f in old_legit_test), len(old_legit_test)
            ),
        }
    report["models"] = models
    report["fresh_train_domains"] = sum(p == "train" for p, _ in fresh_rows.values())

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "fresh.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "fresh.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        return (
            "n/a"
            if not r["n"]
            else f"{100 * r['rate']:.1f}% ({100 * r['ci'][0]:.1f} to {100 * r['ci'][1]:.1f}), {r['k']} of {r['n']}"
        )

    files = ", ".join(f"{f['file']} ({f['downloaded']})" for f in rep["fresh_files"])
    lines = [
        "# Phishing that appeared after the model was fitted (DA4)", "",
        f"{rep['generated_at']}. Fresh files: {files}. {rep['fresh_addresses']:,} addresses, of which {rep['fresh_new_domains']:,} are on a registered domain that none of E1's data held and are kept. Intervals are Wilson 95%.", "",
        "## The whole address engine, as the product runs it", "",
        "| set | flagged (SUSPICIOUS or MALICIOUS) |", "|---|---|",
    ]  # fmt: skip
    lines += [f"| {n} | {pct(r)} |" for n, r in rep["engine"].items()]
    names = list(rep["models"])
    sets = [k for k in rep["models"][names[0]] if k != "threshold"]
    lines += [
        "", "## The domain-name model alone", "",
        f"The fresh train part holds {rep['fresh_train_domains']:,} domains; threshold at 0.4% of E1's calibration legitimate names for both.", "",
        "| read on | " + " | ".join(f"{n} (threshold {rep['models'][n]['threshold']})" for n in names) + " |",
        "|---|" + "---|" * len(names),
    ]  # fmt: skip
    lines += [
        f"| {s} | " + " | ".join(pct(rep["models"][n][s]) for n in names) + " |" for s in sets
    ]
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
