"""DA1: what the two address-rule changes do on E1's TEST split (counts, Wilson 95% intervals).

    python -m eval.da1_rules [--data .data/eval] [--out docs/eval] [--workers N]

Three configurations of the same engine, each run once over the same test URLs, with the learned
model and the popular-domain list on (as the product runs):
  A  before DA1: `url.typosquat` accepts a misspelling of any term of five letters or more, and
     `url.brand_in_domain` fires for a brand inside any word.
  B  A with `url.typosquat` tightened (a misspelling needs a term of six letters or more and the
     brand's first letter or its whole name).
  C  B with `url.brand_in_domain` silent where the brand is only inside a longer word (letters on
     both sides). This is the engine as shipped.
Both changes were chosen on E1's TRAIN split (docs/milestones/DA1.md); this is the first time they
meet the test split. Your browsing (Edge history) is only a false-alarm check, never trained on.
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

from eval import realurl as e1
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")
CONFIGS = {
    "A": "before DA1",
    "B": "typosquat tightened",
    "C": "typosquat and brand-in-domain tightened (shipped)",
}


def setup(cfg: str, data: Path) -> None:
    """Runs once in each judging worker: the engine as it was configured in `cfg`."""
    import rules.url.impersonation as imp
    from core.learn import model
    from core.urls import popular

    popular.configure(data.parent / "popular")
    model.use(model.load(model.DEFAULT))
    if cfg == "A":
        imp._MIN_MISSPELLED = 5
        imp._keeps_the_start = lambda label, term: True
    if cfg in ("A", "B"):
        imp._inside_a_word = lambda label, term: False


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 5) if n else None,
            "ci": [round(ci.low, 5), round(ci.high, 5)] if ci else None}  # fmt: skip


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.da1_rules", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args(list(argv) if argv is not None else None)

    samples = [s for s in e1.load(args.data, 50_000) if e1.split_of(s.url) == "test"]
    groups: dict[str, list[str]] = defaultdict(list)
    for s in samples:
        groups[f"{s.source} {s.label}"].append(s.url)
    urls = sorted({u for g in groups.values() for u in g})
    batch = [e1.Sample("", "", u) for u in urls]
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "configs": CONFIGS,
        "sets": {name: len(g) for name, g in sorted(groups.items())},
        "rows": {},
    }  # fmt: skip
    for cfg in CONFIGS:
        judged = dict(
            zip(urls, e1.judge(batch, args.workers, partial(setup, cfg, args.data)), strict=True)
        )
        report["rows"][cfg] = {
            name: {
                "flagged": _rate(sum(judged[u][0] in FLAGGED for u in g), len(g)),
                "typosquat": sum("url.typosquat" in judged[u][2] for u in g),
                "brand_in_domain": sum("url.brand_in_domain" in judged[u][2] for u in g),
            }
            for name, g in sorted(groups.items())
        }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "da1-rules.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "da1-rules.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        lo, hi = 100 * r["ci"][0], 100 * r["ci"][1]
        return f"{100 * r['rate']:.2f}% ({lo:.2f} to {hi:.2f}), {r['k']} of {r['n']}"

    lines = [
        "# DA1: the typosquat and brand-in-domain changes on E1's test split", "",
        f"{rep['generated_at']}. {' '.join(f'**{k}** = {v}.' for k, v in rep['configs'].items())} "
        "Flagged means SUSPICIOUS or MALICIOUS from the address alone, with the learned model and "
        "the popular-domain list on. The changes were chosen on the train split; this is the "
        "first time they meet the test split. Intervals are Wilson 95%.", "",
        "| set | " + " | ".join(f"flagged {c}" for c in rep["configs"])
        + " | typosquat hits A to C | brand_in_domain hits A to C |",
        "|---|" + "---|" * (len(rep["configs"]) + 2),
    ]  # fmt: skip
    for name in rep["sets"]:
        rows = {c: rep["rows"][c][name] for c in rep["configs"]}
        lines.append(
            f"| {name} | "
            + " | ".join(pct(rows[c]["flagged"]) for c in rep["configs"])
            + f" | {rows['A']['typosquat']} to {rows['C']['typosquat']}"
            + f" | {rows['A']['brand_in_domain']} to {rows['C']['brand_in_domain']} |"
        )
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
