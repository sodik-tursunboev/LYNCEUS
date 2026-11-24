"""List feeds: download a published list, keep it on this machine, match URLs against it locally.

Nothing about the URLs being analysed ever leaves the machine here: the only network traffic is the
periodic download of the list itself (run by the operator with `python -m core.intel sync`).
Each feed is one file, replaced atomically, so a bad download can never leave a half-written or
emptied list. A missing or old list reports UNAVAILABLE; it never reads as "not listed, so fine".
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urljoin, urlsplit

from core.contracts import VerdictState
from core.intel import feedparse
from core.intel.base import (
    Answer,
    Limit,
    ProviderError,
    ProviderRateLimited,
    ProviderUnavailable,
    Query,
    Sends,
    match_hash,
)
from core.intel.http import Client, Fetched, FetchError, check_status, fetch
from core.urls import psl
from core.urls.parse import ParsedUrl, parse_url
from rules.url.data import lists, official_domains

log = logging.getLogger(__name__)
_MAGIC = "lynceus-feed 1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_HOST = 253
MAX_HOPS = 3
SHRINK_GUARD = 0.5  # a new list under half the size of the last good one is not trusted
SHRINK_MIN = 1000  # ...once the last good list was at least this big


def _identity(data: bytes, limit: int) -> bytes:
    if len(data) > limit:
        raise ProviderError("download is over the size limit")
    return data


@dataclass(frozen=True)
class FeedSpec:
    name: str
    title: str
    url: str  # may contain {key}
    allowed_hosts: tuple[str, ...]  # the download and every redirect must end in one of these
    interval: float  # seconds; do not download more often than this
    stale_after: float  # seconds; an older list is reported UNAVAILABLE
    max_download: int
    max_expanded: int
    parse: Callable[[bytes], Iterator[str]]
    expand: Callable[[bytes, int], bytes] = _identity
    keyless_url: str | None = None  # used when no key is configured (None: a key is required)
    note: str = ""  # what is unverified about this feed

    def url_for(self, key: str | None) -> str | None:
        if "{key}" not in self.url:
            return self.url
        return self.url.replace("{key}", key) if key else self.keyless_url


HOUR = 3600.0
FEEDS: dict[str, FeedSpec] = {
    "phishtank": FeedSpec(
        name="phishtank",
        title="PhishTank online-valid",
        url="https://data.phishtank.com/data/{key}/online-valid.json.bz2",
        keyless_url="https://data.phishtank.com/data/online-valid.json.bz2",
        allowed_hosts=("phishtank.com",),
        interval=1 * HOUR,
        stale_after=24 * HOUR,
        max_download=64 * 1024 * 1024,
        max_expanded=256 * 1024 * 1024,
        parse=feedparse.phishtank,
        expand=feedparse.expand_bz2,
        note="Registration status and rate limits unverified; no key: a few downloads a day.",
    ),
    "openphish": FeedSpec(
        name="openphish",
        title="OpenPhish community feed",
        url="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        allowed_hosts=("raw.githubusercontent.com", "openphish.com"),
        interval=12 * HOUR,
        stale_after=36 * HOUR,
        max_download=16 * 1024 * 1024,
        max_expanded=16 * 1024 * 1024,
        parse=feedparse.plain_lines,
        note="Personal and academic use only (OpenPhish terms). Feed contents never fetched here.",
    ),
    "urlhaus": FeedSpec(
        name="urlhaus",
        title="abuse.ch URLhaus export",
        url="https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        allowed_hosts=("abuse.ch",),
        interval=1 * HOUR,
        stale_after=24 * HOUR,
        max_download=64 * 1024 * 1024,
        max_expanded=64 * 1024 * 1024,
        parse=feedparse.urlhaus_csv,
        note="Needs a free Auth-Key; non-commercial use. Export path and CSV layout unverified.",
    ),
}


# ---- storage -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class FeedMeta:
    fetched_at: datetime
    entries: int
    source: str  # host only: never the key
    sha256: str  # of the expanded download
    etag: str | None = None
    last_modified: str | None = None

    def dump(self) -> str:
        return json.dumps(
            {
                "fetched_at": self.fetched_at.isoformat(),
                "entries": self.entries,
                "source": self.source,
                "sha256": self.sha256,
                "etag": self.etag,
                "last_modified": self.last_modified,
            }  # fmt: skip
        )

    @classmethod
    def load(cls, text: str) -> "FeedMeta":
        d = json.loads(text)
        return cls(datetime.fromisoformat(d["fetched_at"]), int(d["entries"]), str(d["source"]),
                   str(d["sha256"]), d.get("etag"), d.get("last_modified"))  # fmt: skip


@dataclass(frozen=True)
class FeedIndex:
    meta: FeedMeta
    urls: frozenset[str] = field(default_factory=frozenset)
    hosts: frozenset[str] = field(default_factory=frozenset)


class FeedStore:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self._loaded: dict[str, tuple[tuple[int, int], FeedIndex]] = {}

    def path(self, name: str) -> Path:
        return self.dir / f"{name}.feed"

    def load(self, name: str) -> FeedIndex | None:
        """The stored list, or None when absent or damaged (a damaged list is treated as absent)."""
        path = self.path(name)
        try:
            stat = path.stat()
            sig = (stat.st_mtime_ns, stat.st_size)
            cached = self._loaded.get(name)
            if cached and cached[0] == sig:
                return cached[1]
            with path.open(encoding="utf-8") as f:
                if f.readline().strip() != _MAGIC:
                    return None
                meta = FeedMeta.load(f.readline())
                urls: set[str] = set()
                hosts: set[str] = set()
                for line in f:
                    tag, _, value = line.rstrip("\n").partition(" ")
                    if tag == "U" and _HEX.match(value):
                        urls.add(value)
                    elif tag == "H" and 0 < len(value) <= _MAX_HOST:
                        hosts.add(value)
        except (OSError, ValueError, KeyError, TypeError):
            return None
        index = FeedIndex(meta, frozenset(urls), frozenset(hosts))
        self._loaded[name] = (sig, index)
        return index

    def _replace(self, name: str, text: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f"{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path(name))
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def write(self, name: str, urls: set[str], hosts: set[str], meta: FeedMeta) -> None:
        lines = [_MAGIC, meta.dump()]
        lines += [f"U {h}" for h in sorted(urls)]
        lines += [f"H {h}" for h in sorted(hosts)]
        self._replace(name, "\n".join(lines) + "\n")

    def touch(self, name: str, fetched_at: datetime) -> None:
        """Mark the stored list as checked just now (the server said it had not changed)."""
        path = self.path(name)
        with path.open(encoding="utf-8") as f:
            magic, meta_line, rest = f.readline(), f.readline(), f.read()
        meta = FeedMeta.load(meta_line)
        updated = FeedMeta(fetched_at, meta.entries, meta.source, meta.sha256, meta.etag,
                           meta.last_modified)  # fmt: skip
        self._replace(name, magic + updated.dump() + "\n" + rest)


# ---- matching ----------------------------------------------------------------------------------


def _host_listing_is_meaningful(host: str) -> bool:
    """A listed host means little on a shared platform or an official domain: skip those."""
    match = psl.lookup(host)
    if match.private or match.registered_domain in official_domains():
        return False
    return not any(host == h or host.endswith("." + h) for h in lists()["shared_hosts"])


class ListFeed:
    """A downloaded list as a provider. Matches on this machine; sends nothing anywhere."""

    sends = Sends.NOTHING
    timeout = 2.0
    limit: Limit | None = None
    ttl = 0.0

    def __init__(
        self,
        spec: FeedSpec,
        store: FeedStore,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.spec, self.store, self.now = spec, store, now
        self.name, self.source = spec.name, spec.title

    async def lookup(self, q: Query) -> Answer:
        index = self.store.load(self.name)
        if index is None:
            raise ProviderUnavailable("feed not downloaded (run: python -m core.intel sync)")
        age = (self.now() - index.meta.fetched_at).total_seconds()
        if age > self.spec.stale_after:
            raise ProviderUnavailable(f"feed is {int(age // HOUR)} hours old")
        provenance = (
            f"{self.spec.title}, checked {index.meta.fetched_at:%Y-%m-%d %H:%MZ}, "
            f"{index.meta.entries} entries"
        )
        if q.url_sha256 and q.url_sha256 in index.urls:
            return Answer(VerdictState.MALICIOUS, provenance, "this URL is on the list",
                          {"listed": "url", "feed": self.name})  # fmt: skip
        if q.host and q.host in index.hosts and _host_listing_is_meaningful(q.host):
            facts = {"listed": "host", "feed": self.name}
            return Answer(
                VerdictState.SUSPICIOUS, provenance, "the host has other listed URLs", facts
            )
        return Answer(VerdictState.UNKNOWN, provenance, "not on the list: this proves nothing")


# ---- sync --------------------------------------------------------------------------------------


class SyncOutcome(NamedTuple):
    feed: str
    status: str  # updated, not_modified, fresh, error
    entries: int
    detail: str


# Told what an update ADDED (feed name, new URL hashes, new hosts, when): the DA5 re-check.
OnNew = Callable[[str, set[str], set[str], datetime], object]  # what it returns is ignored


def _allowed(spec: FeedSpec, url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and any(
        host == h or host.endswith("." + h) for h in spec.allowed_hosts
    )


async def _download(client: Client, spec: FeedSpec, url: str, headers: dict[str, str]) -> Fetched:
    for _ in range(MAX_HOPS + 1):
        got = await fetch(client, "GET", url, max_bytes=spec.max_download, headers=headers)
        if got.status not in (301, 302, 303, 307, 308):
            return got
        url = urljoin(url, got.headers.get("location", ""))
        if not _allowed(spec, url):
            raise FetchError("redirect to a host that is not allowed")
    raise FetchError("too many redirects")


def _index(spec: FeedSpec, expanded: bytes) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    hosts: set[str] = set()
    for raw in spec.parse(expanded):
        if not raw[:8].lower().startswith(("http://", "https://")):
            continue  # the URL parser would guess a scheme for a bare word: a feed entry has one
        parsed = parse_url(raw)
        if isinstance(parsed, ParsedUrl) and parsed.scheme in ("http", "https") and parsed.host:
            urls.add(match_hash(parsed))
            hosts.add(parsed.host)
    return urls, hosts


async def sync(
    spec: FeedSpec,
    store: FeedStore,
    client: Client,
    *,
    key: str | None = None,
    now: datetime | None = None,
    force: bool = False,
    on_new: OnNew | None = None,
) -> SyncOutcome:
    """Download one feed if it is due. The previous good copy survives every failure.

    `on_new` hears what the new list adds to the previous one (all of it on a first download), only
    after the list is stored: a failing hook is logged and never costs the update."""
    now = now or datetime.now(UTC)
    current = store.load(spec.name)
    if current and not force and now - current.meta.fetched_at < timedelta(seconds=spec.interval):
        return SyncOutcome(spec.name, "fresh", current.meta.entries, "downloaded recently")
    url = spec.url_for(key)
    if url is None:
        return SyncOutcome(spec.name, "error", 0, "a key is required and none is configured")
    headers: dict[str, str] = {}
    if current and current.meta.etag:
        headers["If-None-Match"] = current.meta.etag
    if current and current.meta.last_modified:
        headers["If-Modified-Since"] = current.meta.last_modified
    try:
        got = await _download(client, spec, url, headers)
        if got.status == 304 and current:
            store.touch(spec.name, now)
            return SyncOutcome(spec.name, "not_modified", current.meta.entries, "unchanged")
        check_status(got)
        expanded = spec.expand(got.body, spec.max_expanded)
        urls, hosts = _index(spec, expanded)
    except ProviderError as e:  # includes FetchError; reasons are fixed text
        return SyncOutcome(spec.name, "error", 0, e.reason)
    except ProviderRateLimited:
        return SyncOutcome(spec.name, "error", 0, "rate limited; try again later")
    except TimeoutError:
        return SyncOutcome(spec.name, "error", 0, "timeout")
    except Exception:  # noqa: BLE001  (a corrupt download: never echo its content or the URL)
        return SyncOutcome(spec.name, "error", 0, "download could not be read")
    if not urls:
        return SyncOutcome(spec.name, "error", 0, "no usable entries; kept the previous list")
    if (
        current
        and current.meta.entries >= SHRINK_MIN
        and len(urls) < SHRINK_GUARD * current.meta.entries
    ):
        return SyncOutcome(spec.name, "error", 0, "list shrank suspiciously; kept the previous one")
    meta = FeedMeta(
        fetched_at=now,
        entries=len(urls),
        source=urlsplit(url).hostname or "",
        sha256=hashlib.sha256(expanded).hexdigest(),
        etag=got.headers.get("etag"),
        last_modified=got.headers.get("last-modified"),
    )
    store.write(spec.name, urls, hosts, meta)
    if on_new is not None:
        added_urls = urls - (current.urls if current else frozenset())
        added_hosts = hosts - (current.hosts if current else frozenset())
        if added_urls or added_hosts:
            try:
                # ponytail: a failed check is not retried (the entries are no longer new next time)
                await asyncio.to_thread(on_new, spec.name, added_urls, added_hosts, now)
            except Exception:  # noqa: BLE001  (never echo what failed: it may name a site)
                log.warning("the re-check of stored links against %s failed", spec.name)
    return SyncOutcome(spec.name, "updated", len(urls), "ok")


def feed_status(store: FeedStore, names: Iterable[str], now: datetime) -> list[dict[str, Any]]:
    """For the health endpoint and `status`: what is downloaded, how old, whether it is stale."""
    out: list[dict[str, Any]] = []
    for name in sorted(names):
        spec, index = FEEDS[name], store.load(name)
        if index is None:
            out.append({"feed": name, "downloaded": False, "entries": 0, "age_hours": None,
                        "stale": True})  # fmt: skip
            continue
        age = (now - index.meta.fetched_at).total_seconds()
        out.append(
            {"feed": name, "downloaded": True, "entries": index.meta.entries,
             "age_hours": round(age / HOUR, 1), "stale": age > spec.stale_after}
        )  # fmt: skip
    return out
