# ruff: noqa: E501  (report rows are long literals)
"""DA3: what weights should the domain-age signal carry? Fit on sample A, confirm on sample B.

    python -m eval.age_weights [--data .data/eval] [--out docs/eval]

The two samples are public test data asked at the registries by `python -m eval.rdap_age` (A: the default
seed, B: `--seed lynceus-da3-rdap-b --tag b`, none of A's domains): fresh phishing-feed entries, ordinary
Tranco sites at ranks 100,001 to 1,000,000, and a few top-10,000 sites. For every combination of the
three band weights (under 7 days, under 30 days, under 90 days) the whole address engine is scored again
with the age signal added by hand, exactly as `core.risk.correlate` would add it. A weight is chosen
looking at A only (no ordinary site flagged, then the most phishing flagged); B is then read once.
Counts only: no domain is printed.
"""

import argparse
import itertools
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.contracts import Evidence, Signal, VerdictState
from core.detection.engine import UrlAnalysis, analyze_url, rescore
from core.learn import model
from core.urls import popular
from eval import rdap_age
from eval.metrics import wilson
from rules.intel.data import merged_scoring, scoring

FLAGGED = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
GRID = {
    "week": (0.55,),
    "month": (0.40, 0.45, 0.50, 0.55),
    "quarter": (0.15, 0.25, 0.30, 0.35),
}
BANDS = ("week", "month", "quarter")


def band_of(age: int | None) -> str | None:
    t = scoring()["thresholds"]
    if age is None or age < 0:
        return None
    for limit, band in (
        (t["age_week"], "week"),
        (t["age_month"], "month"),
        (t["age_quarter"], "quarter"),
    ):
        if age < limit:
            return band
    return None


def with_age(local: UrlAnalysis, age: int | None, weights: Mapping[str, float]) -> VerdictState:
    band = band_of(age)
    if band is None or local.url is None:
        return local.verdict.state
    rule = f"intel.domain_age.{band}"
    ev = Evidence(
        kind="intel", summary=f"rdap: registered {age} days ago", sha256=local.url.url_sha256
    )
    sig = Signal(rule_id=rule, category="intel.domain_age", weight=weights[band],
                 description=ev.summary, evidence_ids=[ev.id])  # fmt: skip
    again = rescore(local, [sig], [ev], [], cfg=merged_scoring(), note="", version_suffix="age-fit")
    return again.verdict.state


def load(data: Path, tag: str) -> list[dict[str, Any]]:
    """Sample rows with their URLs. A's file predates the URL column: its plan is redrawn from its seed."""
    rows: list[dict[str, Any]] = json.loads(
        (data / "rdap" / f"rows{'-' + tag if tag else ''}.json").read_text("utf-8")
    )
    if rows and "url" not in rows[0]:
        plan = rdap_age.samples(data, "da1-2026-11-16", 300, 250, 50)
        if len(plan) != len(rows):
            raise SystemExit("sample A's plan no longer matches its rows: the feeds changed")
        rows = [r | {"url": u} for r, (_, u) in zip(rows, plan, strict=True)]
    return rows


def rate(k: int, n: int) -> str:
    ci = wilson(k, n)
    return (
        f"{100 * k / n:5.1f}% ({100 * ci.low:.1f} to {100 * ci.high:.1f}) {k}/{n}"
        if n and ci
        else "n/a"
    )


def tally(
    rows: Sequence[Mapping[str, Any]], locals_: Mapping[str, UrlAnalysis], w: Mapping[str, float]
) -> dict[str, tuple[int, int]]:
    out: dict[str, list[int]] = {s: [0, 0] for s in ("phish", "legit_tail", "legit_top")}
    for r in rows:
        out[r["set"]][1] += 1
        out[r["set"]][0] += with_age(locals_[r["url"]], r["age"], w) in FLAGGED
    return {k: (v[0], v[1]) for k, v in out.items()}


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.age_weights", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    args = ap.parse_args(list(argv) if argv is not None else None)
    popular.configure(args.data.parent / "popular")
    model.use(model.load(model.DEFAULT))
    sample = {"A (fit)": load(args.data, ""), "B (confirm)": load(args.data, "b")}
    locals_ = {r["url"]: analyze_url(r["url"]) for rows in sample.values() for r in rows}
    base = {
        n: tally(rows, locals_, {"week": 0.0, "month": 0.0, "quarter": 0.0})
        for n, rows in sample.items()
    }
    now = {b: scoring()["weights"][f"intel.domain_age.{b}"] for b in BANDS}
    combos = [dict(zip(BANDS, c, strict=True)) for c in itertools.product(*GRID.values())]
    results = {n: [(w, tally(rows, locals_, w)) for w in combos] for n, rows in sample.items()}

    # chosen on A only: the fewest ordinary sites flagged, then the most phishing, then the lightest weights
    def key(item: tuple[dict[str, float], dict[str, tuple[int, int]]]) -> tuple[int, int, float]:
        w, t = item
        return (t["legit_tail"][0] + t["legit_top"][0], -t["phish"][0], sum(w.values()))

    best_w, _ = min(results["A (fit)"], key=key)
    report: dict[str, Any] = {"generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"), "weights_now": now, "chosen_on_A": best_w,
                              "samples": {n: len(r) for n, r in sample.items()}, "rows": []}  # fmt: skip
    lines = ["# Domain-age weights (DA3)", "",
             f"{report['generated_at']}. Weights now: {now}. Chosen looking at sample A only: {best_w}. Sample B (no domain in common with A) is the confirmation. Flagged = SUSPICIOUS or MALICIOUS from the address engine plus the age signal. Intervals are Wilson 95%.", ""]  # fmt: skip
    for n in sample:
        lines += [
            f"## Sample {n}",
            "",
            "| band weights (week / month / quarter) | phishing flagged | ordinary long-tail flagged | top sites flagged |",
            "|---|---|---|---|",
        ]
        b = base[n]
        lines.append(
            f"| no age signal | {rate(*b['phish'])} | {rate(*b['legit_tail'])} | {rate(*b['legit_top'])} |"
        )
        for w, t in results[n]:
            tag = " **now**" if w == now else " **chosen**" if w == best_w else ""
            lines.append(
                f"| {w['week']} / {w['month']} / {w['quarter']}{tag} | {rate(*t['phish'])} | {rate(*t['legit_tail'])} | {rate(*t['legit_top'])} |"
            )
            report["rows"].append({"sample": n, "weights": w, "tally": t})
        lines.append("")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "age-weights.json").write_text(
        json.dumps(report, indent=1, default=str), encoding="utf-8"
    )
    (args.out / "age-weights.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
