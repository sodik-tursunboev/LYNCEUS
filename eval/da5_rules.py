# ruff: noqa: E501  (report rows are long literals)
"""DA5 1c and 1d: what the ranked-tier and the two narrowed conditions do, on identical sets.

    python -m eval.da5_rules [--data .data/eval] [--out docs/eval] [--workers N]

Three configurations of the same engine, each run once over the same addresses:
  C  before DA5: the learned model is silent only for the top 100,000 and brand domains; a
     sign-in service's `redirect_uri` is an open redirect at 0.5; `auth` inside `oauth` counts.
  D  C with the learned model also silent for Tranco ranks 100,001 to 1,000,000 (1c).
  E  D with the two narrowed conditions (1d): `redirect_uri` on a sign-in service's own host weighs
     0.3 (url.idp_redirect) and `auth` inside `oauth` is no login word. This is the engine as shipped.
Sets: E1's test split (every source), 3,000 long-tail home pages (Tranco ranks 100,001 to 1M, a
seeded sample), the deep-link corpus (dev and test halves), and your browsing (Edge history, never
trained on). The long tail and the deep links are DRAWN FROM Tranco, so what the ranked tier removes
there is partly circular: the honest evidence for 1c is its COST on phishing (the addresses it stops
flagging are listed in .data/eval/da5/lost.jsonl, public feed data, git-ignored). The deep-link test
half had already been read twice; it is only counted here, never tuned on.
"""

import argparse
import io
import json
import os
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from eval import deeplinks
from eval import realurl as e1
from eval.learn_url import parsed, tail_sample
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")
CONFIGS = {
    "C": "before DA5",
    "D": "C with ranks 100,001 to 1M silencing the learned model (1c)",
    "E": "D with the two narrowed conditions (1d), as shipped",
}


def _ranked_domains(data: Path) -> list[str]:
    from core.urls import popular

    with zipfile.ZipFile(data / "tranco-top-1m.csv.zip") as z:
        member = next(i for i in z.infolist() if i.filename.endswith(".csv"))
        text = io.TextIOWrapper(z.open(member), encoding="ascii", errors="replace").read()
    return popular.ranked_from_csv(text)


def setup(cfg: str, data: Path) -> None:
    """Runs once in each judging worker: the engine as it was configured in `cfg`."""
    import rules.url.content as content
    from core.learn import model
    from core.urls import popular

    popular.configure(data.parent / "popular")
    # the model DA5 started from (kept in .data/eval/da5/model2), so a later model changes nothing here
    pinned = data / "da5" / "model2" / "url_host.json"
    model.use(model.load(pinned if pinned.exists() else model.DEFAULT))
    popular.use_ranked(_ranked_domains(data) if cfg in ("D", "E") else ())
    if cfg in ("C", "D"):
        content._idp_host = lambda host: False
        content._strip_oauth = lambda text: text


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 5) if n else None,
            "ci": [round(ci.low, 5), round(ci.high, 5)] if ci else None}  # fmt: skip


def groups_for(data: Path) -> dict[str, list[str]]:
    """The addresses every DA5 measurement reads: E1's test split, the long tail, the deep links
    (dev and test halves) and your browsing."""
    groups: dict[str, list[str]] = defaultdict(list)
    for s in e1.load(data, 50_000):
        if s.source == "edge_history":
            groups["your browsing (all)"].append(s.url)
        elif e1.split_of(s.url) == "test":
            groups[f"E1 test: {s.source} {s.label}"].append(s.url)
    groups["long tail, 3,000 home pages (Tranco 100,001 to 1M)"] = tail_sample(data, 3000)
    for line in (data / "deeplinks" / "urls.jsonl").read_text("utf-8").splitlines():
        r = json.loads(line)
        u = parsed(r["url"])
        domain = (u.registered_domain if u else None) or r["domain"]
        groups[f"deep links, {deeplinks.split_of(domain)} half"].append(r["url"])
    return dict(groups)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.da5_rules", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args(list(argv) if argv is not None else None)

    groups = groups_for(args.data)
    urls = sorted({u for g in groups.values() for u in g})
    batch = [e1.Sample("", "", u) for u in urls]
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "configs": CONFIGS,
        "sets": {name: len(set(g)) for name, g in sorted(groups.items())},
        "rows": {},
    }  # fmt: skip
    judged_by_cfg: dict[str, dict[str, Any]] = {}
    for cfg in CONFIGS:
        judged = dict(
            zip(urls, e1.judge(batch, args.workers, partial(setup, cfg, args.data)), strict=True)
        )
        judged_by_cfg[cfg] = judged
        report["rows"][cfg] = {
            name: {
                "flagged": _rate(sum(judged[u][0] in FLAGGED for u in set(g)), len(set(g))),
                "rules": {
                    r: sum(r in judged[u][2] for u in set(g) if judged[u][0] in FLAGGED)
                    for r in (
                        "url.learned_domain",
                        "url.idp_redirect",
                        "url.open_redirect",
                        "url.credential_bait",
                    )
                },
            }
            for name, g in sorted(groups.items())
        }
    lost_dir = args.data / "da5"
    lost_dir.mkdir(parents=True, exist_ok=True)
    with (lost_dir / "lost.jsonl").open("w", encoding="utf-8") as f:
        for name, g in sorted(groups.items()):
            if "phish" not in name:
                continue
            for address in sorted(set(g)):
                before = judged_by_cfg["C"][address][0] in FLAGGED
                after = judged_by_cfg["E"][address][0] in FLAGGED
                if before and not after:
                    f.write(json.dumps({"set": name, "url": address}) + "\n")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "da5-rules.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = render(report)
    (args.out / "da5-rules.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        lo, hi = 100 * r["ci"][0], 100 * r["ci"][1]
        return f"{100 * r['rate']:.2f}% ({lo:.2f} to {hi:.2f}), {r['k']} of {r['n']}"

    lines = [
        "# DA5: the ranked tier (1c) and two narrowed conditions (1d), on identical sets", "",
        f"{rep['generated_at']}. {' '.join(f'**{k}** = {v}.' for k, v in rep['configs'].items())} "
        "Flagged means SUSPICIOUS or MALICIOUS from the address alone, with the learned model and the "
        "popular-domain list on. The long tail and the deep links are drawn from Tranco, so the "
        "ranked tier's gain there is partly circular; its cost on phishing is the honest figure. The "
        "deep-link test half was read twice before; here it is only counted. Intervals are Wilson 95%.", "",
        "| set | flagged " + " | flagged ".join(rep["configs"]) + " |",
        "|---|" + "---|" * len(rep["configs"]),
    ]  # fmt: skip
    for name in rep["sets"]:
        lines.append(
            f"| {name} | "
            + " | ".join(pct(rep["rows"][c][name]["flagged"]) for c in rep["configs"])
            + " |"
        )
    return "\n".join([*lines, ""])


if __name__ == "__main__":
    raise SystemExit(main())
