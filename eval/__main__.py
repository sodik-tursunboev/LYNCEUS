"""Run an engine over the corpus and write docs/eval/latest.{json,md}.

python -m eval [--manifest corpus/manifest.jsonl] [--out docs/eval] [--split all|dev|holdout]
"""

import argparse
import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import AwareDatetime, BaseModel

from core.contracts import Artifact, ArtifactKind, Verdict, VerdictState
from core.detection import stub
from eval.corpus import CorpusEntry, Label, load_manifest
from eval.metrics import Counts, Rates, percentile, rates, tally

Analyze = Callable[[Artifact], Verdict]


class Result(BaseModel):
    id: str
    category: str
    label: Label
    state: VerdictState
    latency_ms: float


class Latency(BaseModel):
    p50_ms: float
    p95_ms: float
    max_ms: float


class EvalReport(BaseModel):
    generated_at: AwareDatetime
    engine_version: str
    split: str
    counts: Counts
    rates: Rates
    latency: Latency
    results: list[Result]


def run(entries: list[CorpusEntry], analyze: Analyze, split: str = "all") -> EvalReport:
    chosen = [e for e in entries if split == "all" or e.split.value == split]
    results: list[Result] = []
    version = ""
    for e in chosen:
        art = Artifact(
            kind=ArtifactKind.URL,
            sha256=hashlib.sha256(e.value.encode()).hexdigest(),
            ref=e.value,
        )
        t0 = time.perf_counter()
        v = analyze(art)
        ms = (time.perf_counter() - t0) * 1000
        version = v.engine_version
        results.append(
            Result(id=e.id, category=e.category, label=e.label, state=v.state, latency_ms=ms)
        )
    lat = [r.latency_ms for r in results]
    counts = tally((r.label, r.state) for r in results)
    return EvalReport(
        generated_at=datetime.now(UTC),
        engine_version=version,
        split=split,
        counts=counts,
        rates=rates(counts),
        latency=Latency(
            p50_ms=percentile(lat, 50), p95_ms=percentile(lat, 95), max_ms=max(lat, default=0.0)
        ),
        results=results,
    )


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def render_md(r: EvalReport) -> str:
    c, q = r.counts, r.rates
    return (
        f"# Eval report\n\n"
        f"Engine `{r.engine_version}` | split `{r.split}` | n={c.n} "
        f"| {r.generated_at:%Y-%m-%d %H:%M}Z\n\n"
        f"| TP | FP | FN | TN | abstain (pos/neg) | error (pos/neg) |\n|---|---|---|---|---|---|\n"
        f"| {c.tp} | {c.fp} | {c.fn} | {c.tn} | {c.abstain_pos}/{c.abstain_neg} "
        f"| {c.error_pos}/{c.error_neg} |\n\n"
        f"| precision | recall | recall (answered only) | F1 | abstain rate | error rate |\n"
        f"|---|---|---|---|---|---|\n"
        f"| {_pct(q.precision)} | {_pct(q.recall)} | {_pct(q.recall_answered)} | {_pct(q.f1)} "
        f"| {_pct(q.abstain_rate)} | {_pct(q.error_rate)} |\n\n"
        f"Latency: p50 {r.latency.p50_ms:.3f} ms, p95 {r.latency.p95_ms:.3f} ms, "
        f"max {r.latency.max_ms:.3f} ms.\n\n"
        f"FN counts abstentions and errors on positive samples (ADR-005). "
        f"`n/a` = undefined (zero denominator). Small corpus: treat as a pipeline check, "
        f"not a quality claim.\n"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eval")
    ap.add_argument("--manifest", type=Path, default=Path("corpus/manifest.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    # No "all", no "reserve": dev by default, holdout only on request, reserve stays sealed.
    ap.add_argument("--split", choices=("dev", "holdout"), default="dev")
    args = ap.parse_args(argv)

    report = run(load_manifest(args.manifest), stub.analyze, args.split)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "latest.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    md = render_md(report)
    (args.out / "latest.md").write_text(md, encoding="utf-8", newline="\n")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
