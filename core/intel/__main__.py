"""Operator commands for threat intelligence.

    python -m core.intel sync [--feed NAME ...] [--force]   download the enabled list feeds
    python -m core.intel status                              what is enabled, downloaded, stale
    python -m core.intel lookup <url>                        match a URL against downloaded lists

`sync` is the only command that touches the network, and only to download the lists the operator
enabled in MIRAGE_INTEL_PROVIDERS. `lookup` is offline.
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime

from core.config import Settings
from core.intel.base import Subject
from core.intel.feeds import FEEDS, FeedStore, ListFeed, sync
from core.intel.http import make_client
from core.intel.orchestrator import Intel
from core.urls.parse import ParsedUrl, parse_url


def _keys(s: Settings) -> dict[str, str | None]:
    def secret(v: object) -> str | None:
        return v.get_secret_value() if v is not None and hasattr(v, "get_secret_value") else None

    return {"phishtank": secret(s.phishtank_key), "urlhaus": secret(s.urlhaus_auth_key)}


async def _sync(settings: Settings, names: list[str], force: bool) -> int:
    enabled = settings.intel_enabled() & FEEDS.keys()
    chosen = names or sorted(enabled)
    refused = [n for n in chosen if n not in enabled]
    if refused:
        print(f"not enabled in MIRAGE_INTEL_PROVIDERS: {', '.join(refused)}", file=sys.stderr)
        return 2
    if not chosen:
        print("no list feeds are enabled (set MIRAGE_INTEL_PROVIDERS)")
        return 0
    store, keys, failed = FeedStore(settings.data_dir / "feeds"), _keys(settings), False
    async with make_client(timeout=30.0) as client:
        for name in chosen:
            out = await sync(FEEDS[name], store, client, key=keys.get(name), force=force)
            print(f"{out.feed:10} {out.status:13} {out.entries:>8} entries  {out.detail}")
            failed = failed or out.status == "error"
    return 1 if failed else 0


def _status(settings: Settings) -> int:
    store, now = FeedStore(settings.data_dir / "feeds"), datetime.now(UTC)
    enabled = settings.intel_enabled()
    print("enabled:", ", ".join(sorted(enabled)) or "(none)")
    for name, spec in sorted(FEEDS.items()):
        index = store.load(name)
        if name not in enabled:
            print(f"{name:10} off")
        elif index is None:
            print(f"{name:10} on   not downloaded")
        else:
            hours = (now - index.meta.fetched_at).total_seconds() / 3600
            stale = "STALE" if hours * 3600 > spec.stale_after else "ok"
            print(f"{name:10} on   {index.meta.entries:>8} entries, {hours:.1f} h old, {stale}")
    return 0


async def _lookup(settings: Settings, url: str) -> int:
    parsed = parse_url(url)
    if not isinstance(parsed, ParsedUrl):
        print("not a URL that can be analysed")
        return 2
    store = FeedStore(settings.data_dir / "feeds")
    feeds = [ListFeed(FEEDS[n], store) for n in sorted(settings.intel_enabled() & FEEDS.keys())]
    outcome = await Intel(feeds).query(Subject.from_parsed(parsed))
    for r in outcome.results:
        res = r.result
        state = res.state.value if res.state else "-"
        print(f"{res.provider:10} {res.status.value:12} {state:11} {res.detail or ''}")
    if not outcome.results:
        print("no list feeds are enabled")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.intel")
    commands = ap.add_subparsers(dest="command", required=True)
    s = commands.add_parser("sync", help="download the enabled list feeds")
    s.add_argument("--feed", action="append", default=[], choices=sorted(FEEDS))
    s.add_argument("--force", action="store_true", help="download even if the list is recent")
    commands.add_parser("status", help="show what is enabled and how old each list is")
    lk = commands.add_parser("lookup", help="match one URL against the downloaded lists (offline)")
    lk.add_argument("url")
    args = ap.parse_args(argv)
    settings = Settings()
    if args.command == "sync":
        return asyncio.run(_sync(settings, args.feed, args.force))
    if args.command == "status":
        return _status(settings)
    return asyncio.run(_lookup(settings, args.url))


if __name__ == "__main__":
    raise SystemExit(main())
