# ruff: noqa: E501  (report rows are long literal lines)
"""Measure domain age (RDAP) as a phishing signal, before anyone turns it on (DA1, owner's decision
2026-11-16: measure first, decide after).

    python -m eval.rdap_age [--phish 300] [--tail 250] [--top 50] [--folder da1-2026-11-16]

Sends ONE registered domain name per sample to the registry that runs its top-level domain, through
the product's own RDAP provider and correlation (the same call the API makes), and nothing else.
The samples are public test data only: today's phishing feeds (the DA1 run's copy), a seeded sample
of Tranco ranks 100,001 to 1,000,000 (ordinary sites off the popular list, where an age rule would
fire) and a few Tranco top-10,000 sites. Never the owner's browsing. Domains on shared hosting
(pages.dev, a site builder) are left out: their age is the platform's. Counts only in the report.
"""

import argparse
import asyncio
import json
import random
import re
import tempfile
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.config import Settings
from core.detection.engine import analyze_url
from core.intel.analyze import analyze_with_intel
from core.intel.registry import build_intel
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url
from eval.detonate import phishing
from eval.metrics import wilson
from eval.realurl import tranco
from rules.page import lists as page_lists
from rules.url.data import lists as url_lists

SEED = "lynceus-da1-rdap"
FLAGGED = ("SUSPICIOUS", "MALICIOUS")
_AGE = re.compile(r"registered (\d+) days ago")


def _domain(url: str) -> str | None:
    u = parse_url(url)
    return u.registered_domain if isinstance(u, ParsedUrl) else None


def _shared(domain: str) -> bool:
    entries = [*page_lists()["hosting_platforms"], *url_lists()["shared_hosts"]]
    return any(domain == e or domain.endswith("." + e) for e in entries)


def samples(
    data: Path,
    folder: str,
    n_phish: int,
    n_tail: int,
    n_top: int,
    seed: str = SEED,
    skip: Iterable[str] = (),
) -> list[tuple[str, str]]:
    """(set, url): one URL per registered domain. `skip`: domains already used by another sample,
    so a second sample (DA3) is independent of the first."""
    rng = random.Random(seed)  # noqa: S311  (a reproducible sample, not a secret)
    out: list[tuple[str, str]] = []
    seen: set[str] = set(skip)

    def take(name: str, urls: Sequence[str], n: int) -> None:
        pool = []
        for url in urls:
            d = _domain(url)
            if d and d not in seen and not _shared(d):
                seen.add(d)
                pool.append(url)
        for url in rng.sample(pool, min(n, len(pool))):
            out.append((name, url))

    take("phish", [s.url for s in phishing(data / folder, 5000)], n_phish)
    ranked = [s.url for s in tranco(data / "tranco-top-1m.csv.zip", 1_000_000)]
    take("legit_tail", ranked[100_000:], n_tail)
    take("legit_top", ranked[:10_000], n_top)
    return out


async def measure(
    rows: list[tuple[str, str]], deadline: float, workers: int, per_minute: float
) -> list[dict[str, Any]]:
    """Paced below the provider's own limit (30 a minute): a first run without pacing measured
    mostly that limit (569 RATE_LIMITED), not domain age."""
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            _env_file=None, intel_providers="rdap", intel_deadline=deadline, data_dir=Path(tmp)
        )
        intel = build_intel(settings)
        if intel is None:
            raise RuntimeError("the RDAP provider could not be built")
        gate = asyncio.Semaphore(workers)

        async def one(i: int, name: str, url: str) -> dict[str, Any]:
            await asyncio.sleep(i * 60 / per_minute)
            async with gate:
                before = analyze_url(url).verdict.state.value
                after, outcome = await analyze_with_intel(url, intel)
            answer = next((r.result for r in outcome.results if r.result.provider == "rdap"), None)
            age = _AGE.search(answer.detail or "") if answer is not None and answer.detail else None
            status = answer.status.value if answer is not None else "skipped"
            return {"set": name, "before": before, "after": after.verdict.state.value,
                    "status": status, "age": int(age.group(1)) if age else None}  # fmt: skip

        try:
            return list(await asyncio.gather(*(one(i, n, u) for i, (n, u) in enumerate(rows))))
        finally:
            await intel.aclose()


def _pct(k: int, n: int) -> str:
    ci = wilson(k, n)
    return (
        f"{100 * k / n:.1f}% ({100 * ci.low:.1f} to {100 * ci.high:.1f}), {k} of {n}"
        if n and ci
        else "n/a (n=0)"
    )


def render(rows: list[dict[str, Any]], seed: str = SEED) -> str:
    when = datetime.now(UTC).strftime("%Y-%m-%d %H:%MZ")
    sets = ("phish", "legit_tail", "legit_top")
    lines = [
        "# Domain age (RDAP) as a phishing signal (DA1)",
        "",
        f"{when}. Seed `{seed}`. One registered domain name per sample was sent to its registry through the product's RDAP provider; nothing else was sent. Public test data only (today's phishing feeds; Tranco ranks 100,001 to 1,000,000 as ordinary sites off the popular list; a few Tranco top-10,000 sites); never the owner's browsing. Shared hosting left out. Intervals are Wilson 95%.",
        "",
        "## Did the registry answer with a date?",
        "",
        "| set | domains | age known | no date or no record | failed or skipped |",
        "|---|---|---|---|---|",
    ]
    for s in sets:
        g = [r for r in rows if r["set"] == s]
        known = sum(r["age"] is not None for r in g)
        ok_no_date = sum(r["status"] == "OK" and r["age"] is None for r in g)
        lines.append(
            f"| {s} | {len(g)} | {_pct(known, len(g))} | {ok_no_date} | {len(g) - known - ok_no_date} |"
        )
    lines += [
        "",
        "## How young (of the domains with a known age)",
        "",
        "| set | under 7 days | under 30 days | under 90 days | under 365 days |",
        "|---|---|---|---|---|",
    ]
    for s in sets:
        aged = [r["age"] for r in rows if r["set"] == s and r["age"] is not None]
        lines.append(
            f"| {s} | "
            + " | ".join(_pct(sum(a < d for a in aged), len(aged)) for d in (7, 30, 90, 365))
            + " |"
        )
    lines += [
        "",
        "## What it does to verdicts (today's weights: week 0.55, month 0.4, quarter 0.15)",
        "",
        "| set | flagged by the address rules | flagged with domain age | newly flagged |",
        "|---|---|---|---|",
    ]
    for s in sets:
        g = [r for r in rows if r["set"] == s]
        before = sum(r["before"] in FLAGGED for r in g)
        after = sum(r["after"] in FLAGGED for r in g)
        new = sum(r["after"] in FLAGGED and r["before"] not in FLAGGED for r in g)
        lines.append(f"| {s} | {_pct(before, len(g))} | {_pct(after, len(g))} | {new} |")
    lines += ["", f"Provider status counts: {dict(Counter(r['status'] for r in rows))}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.rdap_age")
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    ap.add_argument(
        "--folder", default="da1-2026-11-16", help="the DA1 run whose phishing feeds to use"
    )
    ap.add_argument("--phish", type=int, default=300)
    ap.add_argument("--tail", type=int, default=250)
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--deadline", type=float, default=15.0, help="seconds to wait for one answer")
    ap.add_argument("--workers", type=int, default=4, help="registries asked at once")
    ap.add_argument("--per-minute", type=float, default=25, help="questions started per minute")
    ap.add_argument("--seed", default=SEED, help="a different seed draws a different sample (DA3)")
    ap.add_argument("--tag", default="", help="file name suffix for a second sample, e.g. b")
    args = ap.parse_args(argv)
    popular.configure(args.data.parent / "popular")  # as the core does (H1 B1)
    skip: set[str] = set()
    if args.seed != SEED:  # independent of the first sample: none of its domains again
        skip = {
            d for _, u in samples(args.data, args.folder, args.phish, args.tail, args.top)
            if (d := _domain(u))
        }  # fmt: skip
    plan = samples(args.data, args.folder, args.phish, args.tail, args.top, args.seed, skip)
    rows = asyncio.run(measure(plan, args.deadline, args.workers, args.per_minute))
    suffix = f"-{args.tag}" if args.tag else ""
    (args.data / "rdap").mkdir(parents=True, exist_ok=True)
    # kept locally (git-ignored): public test URLs only, never the owner's, so a weight can be re-fitted
    (args.data / "rdap" / f"rows{suffix}.json").write_text(
        json.dumps([r | {"url": u} for r, (_, u) in zip(rows, plan, strict=True)]), encoding="utf-8"
    )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"rdap-age{suffix}.md").write_text(render(rows, args.seed), encoding="utf-8")
    print(render(rows, args.seed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
