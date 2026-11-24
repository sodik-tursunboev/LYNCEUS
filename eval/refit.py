# ruff: noqa: E501  (report rows are long literals)
"""DA5 1e: refit the learned domain model on fresher feeds, and measure the whole engine with it.

    python -m eval.refit [--data .data/eval] [--fresh .data/eval/fresh-2026-11-22] [--workers N]

The candidate is fitted on E1's train split plus the train part of the fresh feeds' new domains
(domains E1 never held), with the threshold at 0.4% of E1's calibration legitimate names, exactly
as the shipped model was. It is written to .data/eval/refit/ and NEVER copied into rules/learned by
this tool: adoption is a separate step, taken only if `python -m eval.da5_accept` says the criteria
hold. The engine (as shipped, config E of eval.da5_rules) is then run with the shipped model and with
the candidate over the same addresses: E1's test split, the long tail, the deep links, your browsing,
and the phishing addresses of the fresh feeds that sit on the fresh TEST part (never trained on).
"""

import argparse
import json
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from core.learn.hostfeatures import features
from eval import da5_rules
from eval import realurl as e1
from eval.fresh import fresh_samples
from eval.learn_url import parsed, part, prob, train, write_model
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 5) if n else None,
            "ci": [round(ci.low, 5), round(ci.high, 5)] if ci else None}  # fmt: skip


def setup(which: str, data: Path, candidate: Path) -> None:
    """In each judging worker: the shipped engine with the shipped model or with the candidate."""
    from core.learn import model

    da5_rules.setup("E", data)
    if which == "candidate":
        model.use(model.load(candidate / "url_host.json"))


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.refit", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--fresh", type=Path, default=Path(".data/eval/fresh-2026-11-22"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--epochs", type=int, default=6)
    args = ap.parse_args(list(argv) if argv is not None else None)
    candidate = args.data / "refit"
    candidate.mkdir(parents=True, exist_ok=True)

    old = [s for s in e1.load(args.data, 50_000) if s.source != "edge_history"]
    known_domains = {
        u.registered_domain for s in old if (u := parsed(s.url)) is not None and u.registered_domain
    }
    known_urls = {s.url for s in old}
    new: list[e1.Sample] = []
    seen: set[str] = set()
    for s in fresh_samples(args.fresh):
        u = parsed(s.url)
        if u is None or not u.registered_domain or s.url in known_urls or s.url in seen:
            continue
        if u.registered_domain in known_domains:
            continue
        seen.add(s.url)
        new.append(s)

    rows: dict[tuple[str, int], tuple[str, list[int]]] = {}
    labels_of: dict[str, set[int]] = defaultdict(set)
    for s in old:
        if e1.split_of(s.url) == "reserve":
            continue
        u = parsed(s.url)
        if u is None or not u.registered_domain:
            continue
        y = 1 if s.label == e1.PHISH else 0
        labels_of[u.registered_domain].add(y)
        rows.setdefault((u.registered_domain, y), (part(u.registered_domain), list(features(u))))
    clash = {d for d, ys in labels_of.items() if len(ys) > 1}
    base = [(p, y, f) for (d, y), (p, f) in rows.items() if d not in clash]
    fresh_rows: dict[str, tuple[str, list[int]]] = {}
    for s in new:
        u = parsed(s.url)
        if u is not None and u.registered_domain and u.registered_domain not in clash:
            fresh_rows.setdefault(
                u.registered_domain, (part(u.registered_domain), list(features(u)))
            )

    fit_rows = [(f, y) for p, y, f in base if p == "train"]
    fit_rows += [(f, 1) for p, f in fresh_rows.values() if p == "train"]
    bias, w = train(fit_rows, args.epochs)
    calib = sorted(prob(bias, w, f) for p, y, f in base if p == "calib" and y == 0)
    threshold = max(calib[int(len(calib) * 0.996)], 0.5)
    write_model(candidate, bias, w, threshold)
    header = json.loads((candidate / "url_host.json").read_text("utf-8"))
    header["version"] = "domain-lr-3-candidate"
    header["trained_on"] = (
        "E1 train domains plus the train part of the new domains in the PhishTank and OpenPhish "
        "feeds of 2026-11-22"
    )
    (candidate / "url_host.json").write_text(json.dumps(header, indent=1), encoding="utf-8")

    groups = da5_rules.groups_for(args.data)
    fresh_test = sorted(
        {
            s.url
            for s in new
            if (u := parsed(s.url)) is not None
            and u.registered_domain
            and part(u.registered_domain) == "test"
        }
    )
    groups["fresh feeds, phishing on the fresh TEST part"] = fresh_test
    urls = sorted({u for g in groups.values() for u in g})
    batch = [e1.Sample("", "", u) for u in urls]
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "threshold": {"candidate": round(threshold, 4)},
        "fresh_train_domains": sum(p == "train" for p, _ in fresh_rows.values()),
        "sets": {name: len(set(g)) for name, g in sorted(groups.items())},
        "rows": {},
    }
    for which in ("shipped", "candidate"):
        judged = dict(
            zip(
                urls,
                e1.judge(batch, args.workers, partial(setup, which, args.data, candidate)),
                strict=True,
            )
        )
        report["rows"][which] = {
            name: _rate(sum(judged[u][0] in FLAGGED for u in set(g)), len(set(g)))
            for name, g in sorted(groups.items())
        }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "refit.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "refit.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        lo, hi = 100 * r["ci"][0], 100 * r["ci"][1]
        return f"{100 * r['rate']:.2f}% ({lo:.2f} to {hi:.2f}), {r['k']} of {r['n']}"

    lines = [
        "# DA5 1e: the learned model refitted on fresher feeds, measured in the whole engine", "",
        f"{rep['generated_at']}. Candidate fitted on E1's train split plus {rep['fresh_train_domains']:,} fresh train-part phishing domains (feeds of 2026-11-22), threshold {rep['threshold']['candidate']} at 0.4% of E1's calibration legitimate names. Flagged means SUSPICIOUS or MALICIOUS from the address alone, the engine as shipped (ranked tier and the two narrowed conditions on). The candidate is NOT adopted by this tool. Intervals are Wilson 95%.", "",
        "| set | flagged, shipped model | flagged, candidate |", "|---|---|---|",
    ]  # fmt: skip
    for name in rep["sets"]:
        lines.append(
            f"| {name} | {pct(rep['rows']['shipped'][name])} | {pct(rep['rows']['candidate'][name])} |"
        )
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
