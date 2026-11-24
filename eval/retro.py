"""DA5 re-check gate (docs/milestones/DA5.md, Phase 3, item 1): the retro matcher, measured.

    python -m eval.retro check [--data .data/eval] [--out docs/eval]

Prints RETRO GATE MET only if (a) a scripted case, a stored address that a fake feed then lists,
yields exactly one alert across three reruns (and one audit line), and (b) the same matcher, run
against the 1,640 legitimate deep links of the DA2 corpus stored as pages in a throwaway SQLite
database, yields zero alerts when the fake feed lists none of them but one unrelated address. (A
control, one corpus address listed, must give exactly one exact-address alert: without it, zero
alerts could mean nothing was stored.) The corpus is read, never changed; the throwaway databases
and the fake feeds (the product's own `sync` over httpx.MockTransport) never touch the network.
The report holds counts only.
"""

import argparse
import asyncio
import bz2
import json
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import httpx
from sqlalchemy import Engine, create_engine, func, select

from core.contracts import EventSource
from core.db import models as db
from core.db.store import save_analysis
from core.detection.engine import analyze_url
from core.intel.feeds import FEEDS, FeedStore, sync
from core.intel.http import make_client
from core.retro import alerts, raise_alerts
from core.urls.parse import ParsedUrl, parse_url
from rules.url.data import official_domains

SEEN = "http://retro-case.example/login?id=1"
UNRELATED = "http://retro-unrelated-listing.example/phish.php"
EXTRA = "http://retro-extra-listing.example/"
PHISH = FEEDS["phishtank"]


@contextmanager
def throwaway() -> Iterator[tuple[Engine, FeedStore]]:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        engine = create_engine(f"sqlite:///{Path(d) / 'retro.db'}")
        db.Base.metadata.create_all(engine)
        try:
            yield engine, FeedStore(Path(d) / "feeds")
        finally:
            engine.dispose()


def refresh(engine: Engine, store: FeedStore, urls: Iterable[str]) -> None:
    """One update of a fake feed through the product's `sync`, with the re-check hooked in."""
    body = bz2.compress(json.dumps([{"url": u} for u in urls]).encode())
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=body))

    async def go() -> None:
        async with make_client(transport) as client:
            out = await sync(
                PHISH, store, client, now=datetime.now(UTC), force=True,
                on_new=partial(raise_alerts, engine),
            )  # fmt: skip
            if out.status != "updated":  # the fake feed itself is broken: nothing to measure
                raise RuntimeError(f"the fake feed was not stored: {out.status}")

    asyncio.run(go())


def count(engine: Engine, table: type[db.Base]) -> int:
    with engine.connect() as c:
        return int(c.scalar(select(func.count()).select_from(table)) or 0)


def scripted() -> dict[str, int]:
    out: dict[str, int] = {}
    with throwaway() as (engine, store):
        save_analysis(engine, analyze_url(SEEN), EventSource.BROWSER)
        refresh(engine, store, [UNRELATED])  # the earlier snapshot
        out["before the listing"] = len(alerts(engine))
        refresh(engine, store, [UNRELATED, SEEN])
        out["after the listing"] = len(alerts(engine))
        refresh(engine, store, [UNRELATED, SEEN])  # rerun 1: the same list, nothing is new
        out["after rerun 1 (same list)"] = len(alerts(engine))
        store.path(PHISH.name).unlink()  # rerun 2: the snapshot is lost, every entry looks new
        refresh(engine, store, [UNRELATED, SEEN])
        out["after rerun 2 (snapshot lost)"] = len(alerts(engine))
        refresh(engine, store, [UNRELATED, SEEN, EXTRA])  # rerun 3: the list grew elsewhere
        out["after rerun 3 (list grew)"] = len(alerts(engine))
        with engine.connect() as c:
            audited = c.scalar(
                select(func.count()).select_from(db.AuditLog)
                .where(db.AuditLog.action == "retro.listed")
            )  # fmt: skip
        out["audit lines"] = int(audited or 0)
    return out


def corpus(urls: list[str]) -> dict[str, int]:
    """Store every address as the product does (`analyze_url` then `save_analysis`), refresh a feed
    that lists one unrelated address, then a feed that also lists one of them (the control)."""
    out: dict[str, int] = {}
    with throwaway() as (engine, store):
        for url in urls:
            save_analysis(engine, analyze_url(url), EventSource.BROWSER)
        out["stored pages"] = count(engine, db.Artifact)
        refresh(engine, store, [UNRELATED])  # the first download: every entry is new
        out["feed entries"] = 1
        out["alerts"] = len(alerts(engine))
        listed = next(u for u in urls if _plain(u))
        refresh(engine, store, [UNRELATED, listed])
        out["control: exact-address alerts"] = sum(a["match"] == "url" for a in alerts(engine))
    return out


def _plain(url: str) -> bool:
    """An address a feed could list and the control may use: no fragment (a feed drops it, the
    stored hash keeps it) and not a brand's official domain (those are never raised)."""
    p = parse_url(url)
    return (
        isinstance(p, ParsedUrl)
        and not p.fragment
        and p.registered_domain not in official_domains()
    )


def report(a: dict[str, int], b: dict[str, int], met: bool) -> str:
    rows = [(f"scripted: alerts {k}", v) for k, v in a.items() if k != "audit lines"]
    rows += [("scripted: audit lines", a["audit lines"])]
    rows += [(f"deep links: {k}", v) for k, v in b.items()]
    table = "\n".join(f"| {k} | {v:,} |" for k, v in rows)
    verdict = "RETRO GATE MET" if met else "RETRO GATE FAILED"
    return (
        "# Re-check queue (DA5, Phase 3 item 1)\n\n"
        f"{datetime.now(UTC):%Y-%m-%d %H:%MZ}. Counts only. A stored address that a feed update "
        "lists is raised once (one alert per address and feed, one audit line, the old verdict "
        "untouched). The corpus is the 1,640 legitimate deep links of DA2, stored as pages in a "
        "throwaway database; the fake feed lists one unrelated address. The control lists one "
        f"corpus address.\n\n| case | count |\n|---|---|\n{table}\n\n{verdict}\n"
    )


def check(data: Path, out: Path) -> int:
    path = data / "deeplinks" / "urls.jsonl"
    if not path.exists():
        print(f"FAIL  the deep-link corpus is missing: {path}")
        print("RETRO GATE FAILED: 1")
        return 1
    urls = [json.loads(x)["url"] for x in path.read_text("utf-8").splitlines() if x.strip()]
    a, b = scripted(), corpus(urls)
    results = [
        ("scripted case: one alert after the listing", a["after the listing"] == 1),
        ("scripted case: none before the listing", a["before the listing"] == 0),
        ("scripted case: still one after three reruns",
         {a[k] for k in a if k.startswith("after rerun")} == {1}),
        ("scripted case: one audit line", a["audit lines"] == 1),
        (f"deep links: all {len(urls):,} stored", b["stored pages"] == len(urls)),
        ("deep links: zero alerts", b["alerts"] == 0),
        ("deep links: the control raises exactly one exact-address alert",
         b["control: exact-address alerts"] == 1),
    ]  # fmt: skip
    for what, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {what}")
    failed = [what for what, ok in results if not ok]
    out.mkdir(parents=True, exist_ok=True)
    (out / "retro.md").write_text(report(a, b, not failed), encoding="utf-8", newline="\n")
    print(f"RETRO GATE FAILED: {len(failed)} of {len(results)}" if failed else "RETRO GATE MET")
    return 1 if failed else 0


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.retro", description=__doc__)
    ap.add_argument("command", choices=["check"])
    ap.add_argument("--data", type=Path, default=Path(".data/eval"))
    ap.add_argument("--out", type=Path, default=Path("docs/eval"))
    args = ap.parse_args(list(argv) if argv is not None else None)
    return check(args.data, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
