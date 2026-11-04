"""Run the engine over one corpus split and write docs/eval/<split>.{json,md}.

    python -m eval [--split dev|holdout] [--manifest corpus/manifest.jsonl] [--out docs/eval]

Dev is the default. Holdout must be asked for, and every holdout run is logged in
holdout_runs.md so repeated peeking shows. Reserve is sealed: it cannot be selected here.
"""

import argparse
import hashlib
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import AwareDatetime, BaseModel

from core.contracts import Artifact, ArtifactKind, Verdict, VerdictState
from core.detection.engine import analyze as engine_analyze
from eval.corpus import CorpusEntry, Label, load_manifest
from eval.metrics import Counts, Interval, Rates, percentile, rates, tally, wilson
from rules.url import RULES

Analyze = Callable[[Artifact], Verdict]
CAVEAT = (
    "**Synthetic positives measure rule correctness, not the real-world detection rate.** "
    "The same author wrote the rules and the corpus, from shared templates."
)


class Result(BaseModel):
    id: str
    category: str
    label: Label
    state: VerdictState
    rules: list[str]
    latency_ms: float


class Latency(BaseModel):
    p50_ms: float
    p95_ms: float
    max_ms: float


class RuleStat(BaseModel):
    rule_id: str
    hits: int
    on_malicious: int
    on_benign: int
    precision: float  # share of this rule's hits that landed on malicious samples
    precision_ci: Interval | None


class EvalReport(BaseModel):
    generated_at: AwareDatetime
    engine_version: str
    ruleset_version: str
    split: str
    samples_sha256: str  # of the evaluated ids and URLs
    counts: Counts
    rates: Rates
    latency: Latency
    rules: list[RuleStat]
    results: list[Result]


def rule_stats(results: Sequence[Result]) -> list[RuleStat]:
    hits: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in results:
        for rule_id in r.rules:
            hits[rule_id][r.label is Label.BENIGN] += 1
    return [
        RuleStat(
            rule_id=rule_id,
            hits=bad + good,
            on_malicious=bad,
            on_benign=good,
            precision=bad / (bad + good),
            precision_ci=wilson(bad, bad + good),
        )
        for rule_id, (bad, good) in sorted(hits.items())
    ]


def _artifact(e: CorpusEntry) -> Artifact:
    digest = hashlib.sha256(e.value.encode()).hexdigest()
    return Artifact(kind=ArtifactKind.URL, sha256=digest, ref=e.value)


def run(entries: list[CorpusEntry], analyze: Analyze, split: str = "all") -> EvalReport:
    chosen = [e for e in entries if split == "all" or e.split.value == split]
    pairs = [(e, _artifact(e)) for e in chosen]
    if pairs:
        analyze(pairs[0][1])  # warm up: data files load once and would dominate the first sample
    results: list[Result] = []
    engine = ruleset = ""
    for e, art in pairs:
        t0 = time.perf_counter()
        v = analyze(art)
        ms = (time.perf_counter() - t0) * 1000
        engine, ruleset = v.engine_version, v.ruleset_version
        names = [s.rule_id for s in v.signals]
        results.append(
            Result(
                id=e.id,
                category=e.category,
                label=e.label,
                state=v.state,
                rules=names,
                latency_ms=ms,
            )
        )
    lat = [r.latency_ms for r in results]
    counts = tally((r.label, r.state) for r in results)
    return EvalReport(
        generated_at=datetime.now(UTC),
        engine_version=engine,
        ruleset_version=ruleset,
        split=split,
        samples_sha256=hashlib.sha256(
            "\n".join(f"{e.id} {e.value}" for e in chosen).encode("utf-8", "surrogatepass")
        ).hexdigest(),
        counts=counts,
        rates=rates(counts),
        latency=Latency(
            p50_ms=percentile(lat, 50), p95_ms=percentile(lat, 95), max_ms=max(lat, default=0.0)
        ),
        rules=rule_stats(results),
        results=results,
    )


def _num(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def _ci(i: Interval | None) -> str:
    return "n/a" if i is None else f"{i.low:.3f} to {i.high:.3f}"


def render_md(r: EvalReport) -> str:
    c, q = r.counts, r.rates
    lines = [
        "# Eval report",
        "",
        f"Split `{r.split}`, n={c.n}. Engine `{r.engine_version}`, "
        f"ruleset `{r.ruleset_version}`. {r.generated_at:%Y-%m-%d %H:%M}Z.",
        "",
        CAVEAT,
        "",
        "| TP | FP | FN | TN | abstain (malicious / benign) | error (malicious / benign) |",
        "|---|---|---|---|---|---|",
        f"| {c.tp} | {c.fp} | {c.fn} | {c.tn} | {c.abstain_pos} / {c.abstain_neg} "
        f"| {c.error_pos} / {c.error_neg} |",
        "",
        "| Metric | Value | Wilson 95% interval |",
        "|---|---|---|",
        f"| Precision | {_num(q.precision)} | {_ci(q.precision_ci)} |",
        f"| Recall (abstentions are misses) | {_num(q.recall)} | {_ci(q.recall_ci)} |",
        f"| Recall (answered only) | {_num(q.recall_answered)} | |",
        f"| F1 | {_num(q.f1)} | |",
        f"| Flag rate on benign (UNKNOWN is not flagged) | {_num(q.flag_rate)} "
        f"| {_ci(q.flag_rate_ci)} |",
        f"| Abstain rate | {_num(q.abstain_rate)} | {_ci(q.abstain_ci)} |",
        f"| Error rate | {_num(q.error_rate)} | |",
        "",
        f"Latency per URL: p50 {r.latency.p50_ms:.3f} ms, p95 {r.latency.p95_ms:.3f} ms, "
        f"max {r.latency.max_ms:.3f} ms. Wall time on a shared development machine: the same code "
        "measured 1.4 ms and 14 ms p50 hours apart, so read it as an order of magnitude.",
        "",
        "## Rules",
        "",
        "Precision here is the share of a rule's hits on malicious samples. "
        "Weak rules are meant to be low: they only count in combination.",
        "",
        "| Rule | Hits | Malicious | Benign | Precision | Wilson 95% interval |",
        "|---|---|---|---|---|---|",
    ]
    for s in r.rules:
        lines.append(
            f"| `{s.rule_id}` | {s.hits} | {s.on_malicious} | {s.on_benign} "
            f"| {s.precision:.3f} | {_ci(s.precision_ci)} |"
        )
    silent = sorted({rule.id for rule in RULES} - {s.rule_id for s in r.rules})
    lines += [
        "",
        f"Rules with no hits on this split: {', '.join(f'`{s}`' for s in silent) or 'none'}.",
        "",
        "FN counts abstentions and errors on malicious samples (ADR-005). "
        "`n/a` means undefined (zero denominator).",
        "",
    ]
    return "\n".join(lines)


def log_holdout(r: EvalReport, out: Path) -> None:
    path = out / "holdout_runs.md"
    if not path.exists():
        path.write_text(
            "# Holdout runs\n\nEvery holdout run is recorded here. Never tune against these.\n\n"
            "| Date (UTC) | Ruleset | n | TP | FP | FN | Precision | Recall | Flag rate "
            "| Abstain |\n|---|---|---|---|---|---|---|---|---|---|\n",
            encoding="utf-8",
            newline="\n",
        )
    c, q = r.counts, r.rates
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(
            f"| {r.generated_at:%Y-%m-%d %H:%M} | `{r.ruleset_version}` | {c.n} | {c.tp} | {c.fp} "
            f"| {c.fn} | {_num(q.precision)} | {_num(q.recall)} | {_num(q.flag_rate)} "
            f"| {_num(q.abstain_rate)} |\n"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eval")
    ap.add_argument("--manifest", type=Path, default=Path("corpus/manifest.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    # No "all", no "reserve": dev by default, holdout only on request, reserve stays sealed.
    ap.add_argument("--split", choices=("dev", "holdout"), default="dev")
    args = ap.parse_args(argv)

    report = run(load_manifest(args.manifest), engine_analyze, args.split)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"{args.split}.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    md = render_md(report)
    (args.out / f"{args.split}.md").write_text(md, encoding="utf-8", newline="\n")
    if args.split == "holdout":
        log_holdout(report, args.out)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
