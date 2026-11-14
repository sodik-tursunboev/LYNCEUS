"""Operator commands for threat intelligence.

    python -m core.intel sync [--feed NAME ...] [--force]   download the enabled list feeds
    python -m core.intel status                              what is enabled, downloaded, stale
    python -m core.intel lookup <url>                        match a URL against downloaded lists
    python -m core.intel hashes status|import|check|sync     known-bad file hashes (offline lookup)
    python -m core.intel popular sync|status                 the popular-domain list (H1 B1)

`sync`, `hashes sync` and `popular sync` are the only commands that touch the network, and only
to download lists
the operator asked for (the feeds in LYNCEUS_INTEL_PROVIDERS; MalwareBazaar's hashes with the
operator's own abuse.ch key). `lookup` and the other `hashes` commands are offline.
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

from core import hashlists
from core.config import Settings
from core.intel import hashfeed
from core.intel import popular as popular_sync
from core.intel.base import Subject
from core.intel.feeds import FEEDS, FeedStore, ListFeed, sync
from core.intel.http import make_client
from core.intel.orchestrator import Intel
from core.intel.refresh import feed_keys
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url


async def _sync(settings: Settings, names: list[str], force: bool) -> int:
    enabled = settings.intel_enabled() & FEEDS.keys()
    chosen = names or sorted(enabled)
    refused = [n for n in chosen if n not in enabled]
    if refused:
        print(f"not enabled in LYNCEUS_INTEL_PROVIDERS: {', '.join(refused)}", file=sys.stderr)
        return 2
    if not chosen:
        print("no list feeds are enabled (set LYNCEUS_INTEL_PROVIDERS)")
        return 0
    store, keys, failed = FeedStore(settings.data_dir / "feeds"), feed_keys(settings), False
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


def _hashes(settings: Settings, args: argparse.Namespace) -> int:
    directory = settings.data_dir / "hashes"
    if args.action == "status":
        hashlists.configure(directory)
        print(f"folder: {directory}")
        for info in hashlists.current().status():
            print(f"{info.name:24} {info.hashes:>10} hashes")
        return 0
    if args.action == "import":
        source = Path(args.file)
        if not source.is_file():
            print("no such file", file=sys.stderr)
            return 2
        try:
            kept = hashlists.import_list(source, args.name, directory)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        print(f"kept {kept} hashes as {args.name.lower()} in {directory}")
        return 0
    if args.action == "check":
        target = Path(args.file)
        if not target.is_file():
            print("no such file", file=sys.stderr)
            return 2
        hashlists.configure(directory)
        found = hashlists.digests_of_file(target)
        for algorithm, value in found.items():
            print(f"{algorithm:7} {value}")
        hits = hashlists.current().lookup(found)
        for algorithm, list_name in hits:
            print(f"KNOWN BAD: the {algorithm} is on the list '{list_name}'")
        if not hits:
            lists = len(hashlists.current().status())
            print(f"no match in {lists} list(s) (that is not a sign of safety)")
        return 1 if hits else 0
    key = settings.urlhaus_auth_key.get_secret_value() if settings.urlhaus_auth_key else None

    async def run() -> int:
        async with make_client(timeout=60.0) as client:
            status, count, detail = await hashfeed.sync(directory, client, key, force=args.force)
        print(f"{hashfeed.NAME:14} {status:8} {count:>9} hashes  {detail}")
        return 1 if status == "error" else 0

    return asyncio.run(run())


def _popular(settings: Settings, action: str) -> int:
    directory = settings.data_dir / "popular"
    if action == "status":
        popular.configure(directory)
        print(f"{len(popular.domains())} popular domains in {directory / popular.FILE}")
        return 0

    async def run() -> int:
        async with make_client(timeout=60.0) as client:
            try:
                kept, detail = await popular_sync.sync(directory, client)
            except Exception as e:  # noqa: BLE001  (a stated failure; the old list stays in place)
                print(f"popular   error    {type(e).__name__}: {e}", file=sys.stderr)
                return 1
        print(f"popular   ok       {kept:>9} domains  {detail}")
        return 0

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.intel")
    commands = ap.add_subparsers(dest="command", required=True)
    h = commands.add_parser("hashes", help="known-bad file hash lists on this machine")
    actions = h.add_subparsers(dest="action", required=True)
    actions.add_parser("status", help="the lists loaded and how many hashes each holds")
    imp = actions.add_parser("import", help="add a list of hashes (SHA-256, SHA-1 or MD5 per line)")
    imp.add_argument("file")
    imp.add_argument("--name", required=True, help="the list's name, shown in verdicts")
    chk = actions.add_parser("check", help="hash a file here and look it up (offline)")
    chk.add_argument("file")
    snc = actions.add_parser(
        "sync", help="download MalwareBazaar's recent hashes (needs your Auth-Key)"
    )
    snc.add_argument("--force", action="store_true", help="ignore the five-minute minimum")
    s = commands.add_parser("sync", help="download the enabled list feeds")
    s.add_argument("--feed", action="append", default=[], choices=sorted(FEEDS))
    s.add_argument("--force", action="store_true", help="download even if the list is recent")
    commands.add_parser("status", help="show what is enabled and how old each list is")
    lk = commands.add_parser("lookup", help="match one URL against the downloaded lists (offline)")
    lk.add_argument("url")
    pop = commands.add_parser("popular", help="the popular-domain list used by look-alike rules")
    pop.add_argument("action", choices=["sync", "status"])
    args = ap.parse_args(argv)
    settings = Settings()
    if args.command == "hashes":
        return _hashes(settings, args)
    if args.command == "popular":
        return _popular(settings, args.action)
    if args.command == "sync":
        return asyncio.run(_sync(settings, args.feed, args.force))
    if args.command == "status":
        return _status(settings)
    return asyncio.run(_lookup(settings, args.url))


if __name__ == "__main__":
    raise SystemExit(main())
