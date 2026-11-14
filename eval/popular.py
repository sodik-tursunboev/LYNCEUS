"""H1 B1: what the popular-domain list changes, measured before and after on data already on disk.

    python -m eval.popular [--data .data/eval] [--out docs/eval] [--workers N]

The list is pinned to the Tranco copy E1 downloaded (`.data/eval/tranco-top-1m.csv.zip`,
2026-11-10),
top 100,000, so the numbers can be reproduced. Nothing is opened or fetched: E1 is lexical, and D1's
pages are re-judged from what was kept (`eval.detonate --rescore`). Edge's history is read as E1
does (local, counts only).

How to read it: the list can only change a verdict for a URL whose registered domain is on it. So
the report says, per set, how much of it sits on popular domains, what the list cleared there, and
what it cost on phishing. Legitimate sets drawn from Tranco itself are cleared by construction and
are shown apart; the honest false-alarm figures are the other legitimate sets. The rules were
changed by looking at D1's dev half and E1's train split only; the test numbers here are the
second look at those halves, recorded in docs/milestones/H1.md.
"""

import argparse
import json
import os
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eval import detonate as d1
from eval import realurl as e1
from eval.metrics import wilson

FLAGGED = ("SUSPICIOUS", "MALICIOUS")


def pinned(data: Path) -> frozenset[str]:
    from core.urls import popular

    with zipfile.ZipFile(data / "tranco-top-1m.csv.zip") as z:
        text = z.read(z.namelist()[0]).decode("ascii", "replace")
    return frozenset(popular.top_from_csv(text))


def _init(domains: frozenset[str]) -> None:
    from core.urls import popular

    popular.configure(None)
    popular.use(domains)


def _states(urls: Sequence[str]) -> list[str]:
    from core.detection.engine import analyze_url

    out = []
    for url in urls:
        try:
            out.append(analyze_url(url).verdict.state.value)
        except Exception:  # noqa: BLE001  (counted, never "safe")
            out.append("ERROR")
    return out


def judge(urls: Sequence[str], domains: frozenset[str], workers: int) -> list[str]:
    chunks = [urls[i : i + 2000] for i in range(0, len(urls), 2000)]
    with ProcessPoolExecutor(max_workers=workers, initializer=_init, initargs=(domains,)) as pool:
        return [s for part in pool.map(_states, chunks) for s in part]


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None,
            "ci": [round(ci.low, 4), round(ci.high, 4)] if ci else None}  # fmt: skip


def _registered(url: str) -> str | None:
    from core.urls.parse import ParsedUrl, parse_url

    u = parse_url(url)
    return u.registered_domain if isinstance(u, ParsedUrl) else None


def compare(
    groups: Mapping[str, Sequence[tuple[str, str, str]]], domains: frozenset[str]
) -> dict[str, Any]:
    """groups: name -> [(url, state before, state after)]."""
    out = {}
    for name, rows in groups.items():
        on_list = [r for r in rows if _registered(r[0]) in domains]
        out[name] = {
            "n": len(rows),
            "on_popular_domains": _rate(len(on_list), len(rows)),
            "flagged_before": _rate(sum(b in FLAGGED for _, b, _ in rows), len(rows)),
            "flagged_after": _rate(sum(a in FLAGGED for _, _, a in rows), len(rows)),
            "cleared_by_the_list": sum(b in FLAGGED and a not in FLAGGED for _, b, a in rows),
            "newly_flagged": sum(a in FLAGGED and b not in FLAGGED for _, b, a in rows),
        }
    return out


def e1_groups(data: Path, domains: frozenset[str], workers: int) -> dict[str, Any]:
    samples = [s for s in e1.load(data, 50_000) if e1.split_of(s.url) != "reserve"]
    urls = [s.url for s in samples]
    before, after = judge(urls, frozenset(), workers), judge(urls, domains, workers)
    groups: dict[str, list[tuple[str, str, str]]] = {}
    for s, b, a in zip(samples, before, after, strict=True):
        tranco = " (from Tranco: circular)" if s.source == "tranco" else ""
        name = f"{e1.split_of(s.url)} {s.source} {s.label}{tranco}"
        groups.setdefault(name, []).append((s.url, b, a))
    return compare(dict(sorted(groups.items())), domains)


def d1_groups(data: Path, domains: frozenset[str]) -> dict[str, Any]:
    from core.urls import popular

    samples = d1.phishing(data / "d1", 400) + d1.legitimate(data, 400) + d1.sign_in_pages(data, 300)
    pages = data / "d1" / "pages"
    popular.use(frozenset())
    before = {r["url"]: r for r in d1.rescore(samples, pages)}
    popular.use(domains)
    after = {r["url"]: r for r in d1.rescore(samples, pages)}
    popular.use(frozenset())
    groups: dict[str, list[tuple[str, str, str]]] = {}
    for url, b in before.items():
        if not b["alive"]:
            continue  # as in D1: rates on pages that were alive
        tranco = " (from Tranco: circular)" if b["source"].startswith("tranco") else ""
        name = f"{b['split']} {b['source']} {b['label']}{tranco}"
        groups.setdefault(name, []).append((url, b["state"], after[url]["state"]))
    return compare(dict(sorted(groups.items())), domains)


def render(rep: Mapping[str, Any]) -> str:
    def pct(r: Mapping[str, Any]) -> str:
        if not r["n"]:
            return "-"
        low, high = 100 * r["ci"][0], 100 * r["ci"][1]
        return f"{100 * r['rate']:.1f}% ({low:.1f} to {high:.1f}), {r['k']} of {r['n']}"

    lines = [
        "# Popular-domain list: before and after (H1 B1)", "",
        f"{rep['generated_at']}. List pinned to E1's Tranco copy, top {rep['list_size']:,} "
        "registered domains. Nothing was opened or fetched. Legitimate sets drawn from Tranco are "
        "cleared by construction and marked *circular*; read the other legitimate sets for the "
        "false-alarm change. Rules were changed by looking at D1 dev and E1 train only.", "",
    ]  # fmt: skip
    for title, key in (("D1: live pages, URL rules + page (alive pages)", "d1"),
                       ("E1: URL rules alone", "e1")):  # fmt: skip
        lines += [f"## {title}", "", "| set | on popular domains | flagged before | flagged after "
                  "| cleared | newly flagged |", "|---|---|---|---|---|---|"]  # fmt: skip
        for name, r in rep[key].items():
            lines.append(f"| {name} | {pct(r['on_popular_domains'])} | {pct(r['flagged_before'])} "
                         f"| {pct(r['flagged_after'])} | {r['cleared_by_the_list']} "
                         f"| {r['newly_flagged']} |")  # fmt: skip
        lines.append("")
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.popular", description=__doc__)
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args(list(argv) if argv is not None else None)
    domains = pinned(args.data)
    rep = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ"),
        "list_size": len(domains),
        "d1": d1_groups(args.data, domains),
        "e1": e1_groups(args.data, domains, args.workers),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "popular.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
    (args.out / "popular.md").write_text(render(rep), encoding="utf-8")
    print(render(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
