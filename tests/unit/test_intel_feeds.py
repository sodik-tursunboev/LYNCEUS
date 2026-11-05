"""List feeds: parsers, the on-disk store, matching, and sync with failures injected.
Downloads use httpx.MockTransport: no socket is ever opened."""

import asyncio
import bz2
import json
import logging
import os
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.contracts import ProviderStatus, VerdictState
from core.intel import feedparse
from core.intel.base import ProviderError, ProviderUnavailable, Query, Subject
from core.intel.feeds import (
    FEEDS,
    FeedMeta,
    FeedStore,
    ListFeed,
    SyncOutcome,
    sync,
)
from core.intel.http import make_client
from core.intel.orchestrator import Intel
from core.urls.parse import ParsedUrl, parse_url
from rules.url.data import lists

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
KEY = "KEY-SECRET-123"
PHISH = FEEDS["phishtank"]
HOURS = 3600


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def phishtank_file(urls: list[str]) -> bytes:
    return bz2.compress(
        json.dumps([{"phish_id": str(i), "url": u} for i, u in enumerate(urls)]).encode()
    )


def query(url: str) -> Query:
    p = parse_url(url)
    assert isinstance(p, ParsedUrl)
    s = Subject.from_parsed(p)
    return Query(name=s.name, host=s.host, url_sha256=s.url_sha256)


class Server:
    """Records requests; `reply` decides the response."""

    def __init__(self, reply: Callable[[httpx.Request], httpx.Response] | httpx.Response) -> None:
        self.reply, self.requests = reply, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.reply, httpx.Response):
            return self.reply
        return self.reply(request)

    def client(self) -> httpx.AsyncClient:
        return make_client(httpx.MockTransport(self))


def do_sync(
    store: FeedStore, server: Server, spec: Any = PHISH, *, key: str | None = None,
    now: datetime = NOW, force: bool = False,
) -> SyncOutcome:  # fmt: skip
    async def go() -> SyncOutcome:
        async with server.client() as client:
            return await sync(spec, store, client, key=key, now=now, force=force)

    return run(go())  # type: ignore[no-any-return]


@pytest.fixture
def store(tmp_path: Path) -> FeedStore:
    return FeedStore(tmp_path / "feeds")


def ok_server(urls: list[str], **headers: str) -> Server:
    return Server(httpx.Response(200, content=phishtank_file(urls), headers=headers))


# ---- parsers -------------------------------------------------------------------------------------


def test_phishtank_parser_takes_urls_and_ignores_the_rest() -> None:
    data = json.dumps([{"url": "http://a.test/x"}, {"url": 5}, {"nope": 1}, "str", {"url": ""}])
    assert list(feedparse.phishtank(data.encode())) == ["http://a.test/x"]


@pytest.mark.parametrize("data", [b"not json", b'{"url": "x"}', b"", b"[" * 100_000])
def test_phishtank_parser_rejects_a_feed_of_the_wrong_shape(data: bytes) -> None:
    with pytest.raises(ProviderError):
        list(feedparse.phishtank(data))


def test_plain_lines_skip_blanks_comments_and_overlong_lines() -> None:
    data = (
        b"http://a.test/1\n\n# comment\n  http://b.test/2  \n"
        + b"http://c.test/"
        + b"x" * 9000
        + b"\n"
    )
    assert list(feedparse.plain_lines(data)) == ["http://a.test/1", "http://b.test/2"]


def test_urlhaus_csv_uses_the_header_and_skips_offline_rows() -> None:
    data = (
        b"# URLhaus export\n"
        b"# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        b'1,2026-11-01,"http://m1.test/a.exe",online,2026-11-02,malware_download,,x,r\n'
        b"2,2026-11-01,http://m2.test/b,offline,2026-11-02,malware_download,,x,r\n"
        b"3,short\n"
    )
    assert list(feedparse.urlhaus_csv(data)) == ["http://m1.test/a.exe"]


def test_urlhaus_csv_without_a_named_header_uses_the_documented_layout() -> None:
    data = b"# just a comment\n1,2026-11-01,http://m1.test/a,online\n2,2026-11-01,http://m2.test/b,offline\n"
    assert list(feedparse.urlhaus_csv(data)) == ["http://m1.test/a"]


def test_a_urlhaus_layout_that_puts_no_urls_where_expected_yields_no_entries(
    store: FeedStore,
) -> None:
    csv = b"# a,b,c\n1,2,3\n4,5,6\n"
    out = do_sync(store, Server(httpx.Response(200, content=csv)), FEEDS["urlhaus"], key="k")
    assert out.status == "error" and "no usable entries" in out.detail


def test_bz2_expansion_is_capped() -> None:
    bomb = bz2.compress(b"0" * (5 * 1024 * 1024))
    assert len(bomb) < 10_000
    with pytest.raises(ProviderError):
        feedparse.expand_bz2(bomb, 1024 * 1024)
    assert feedparse.expand_bz2(bz2.compress(b"abc"), 1024) == b"abc"


# ---- store ---------------------------------------------------------------------------------------


def meta(entries: int = 2, at: datetime = NOW) -> FeedMeta:
    return FeedMeta(at, entries, "data.phishtank.com", "ab" * 32, 'W/"e1"', None)


def test_the_store_round_trips_and_caches_by_file_signature(store: FeedStore) -> None:
    store.write("phishtank", {"a" * 64, "b" * 64}, {"x.test"}, meta())
    first = store.load("phishtank")
    assert first and first.urls == {"a" * 64, "b" * 64} and first.hosts == {"x.test"}
    assert first.meta.etag == 'W/"e1"' and store.load("phishtank") is first
    store.write("phishtank", {"c" * 64}, set(), meta(1))
    second = store.load("phishtank")
    assert second and second.urls == {"c" * 64} and second is not first


@pytest.mark.parametrize(
    "content",
    ["", "wrong-magic\n{}\n", "mirage-feed 1\nnot json\n", 'mirage-feed 1\n{"entries": 1}\n'],
)
def test_a_damaged_file_is_treated_as_absent(store: FeedStore, content: str) -> None:
    store.dir.mkdir(parents=True)
    store.path("phishtank").write_text(content, encoding="utf-8")
    assert store.load("phishtank") is None


def test_junk_lines_in_a_good_file_are_ignored(store: FeedStore) -> None:
    store.write("phishtank", {"a" * 64}, set(), meta(1))
    with store.path("phishtank").open("a", encoding="utf-8") as f:
        f.write("U not-a-hash\nH " + "h" * 300 + "\nZ whatever\n\n")
    index = store.load("phishtank")
    assert index and index.urls == {"a" * 64} and index.hosts == set()


def test_a_failed_write_leaves_the_old_list_and_no_temp_file(
    store: FeedStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.write("phishtank", {"a" * 64}, set(), meta(1))

    def boom(*_a: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.write("phishtank", {"b" * 64}, set(), meta(1))
    monkeypatch.undo()
    assert store.load("phishtank").urls == {"a" * 64}  # type: ignore[union-attr]
    assert [p.name for p in store.dir.iterdir()] == ["phishtank.feed"]


# ---- matching ------------------------------------------------------------------------------------


def stored(store: FeedStore, urls: list[str], at: datetime = NOW) -> ListFeed:
    do_sync(store, ok_server(urls), now=at)
    return ListFeed(PHISH, store, now=lambda: NOW)


def lookup(feed: ListFeed, url: str) -> Any:
    return run(feed.lookup(query(url)))


def test_an_exact_url_match_is_malicious_and_ignores_url_spelling(store: FeedStore) -> None:
    feed = stored(store, ["HTTP://Evil-Site.TEST:80/Login?a=1#top"])
    answer = lookup(feed, "http://evil-site.test/Login?a=1")
    assert answer.state is VerdictState.MALICIOUS and answer.facts == {
        "listed": "url",
        "feed": "phishtank",
    }
    assert "PhishTank" in answer.provenance and "1 entries" in answer.provenance


def test_a_listed_host_with_another_path_is_only_suspicious(store: FeedStore) -> None:
    feed = stored(store, ["http://evil-site.test/kit/login.php"])
    answer = lookup(feed, "http://evil-site.test/other")
    assert answer.state is VerdictState.SUSPICIOUS and answer.facts["listed"] == "host"


def test_not_listed_is_unknown_never_benign(store: FeedStore) -> None:
    feed = stored(store, ["http://evil-site.test/a"])
    answer = lookup(feed, "http://clean-site.test/")
    assert answer.state is VerdictState.UNKNOWN and "proves nothing" in (answer.detail or "")


def test_a_listing_on_a_shared_or_official_or_multi_tenant_host_does_not_taint_the_host(
    store: FeedStore,
) -> None:
    shared = lists()["shared_hosts"][0]
    feed = stored(
        store,
        [f"http://{shared}/phish/1", "https://www.paypal.com/x/1", "http://someone.github.io/kit"],
    )
    for other in (
        f"http://{shared}/legit",
        "https://www.paypal.com/y",
        "http://another.github.io/",
    ):
        assert lookup(feed, other).state is VerdictState.UNKNOWN, other
    # ...but an exact URL match on those hosts still counts
    assert lookup(feed, f"http://{shared}/phish/1").state is VerdictState.MALICIOUS


def test_no_list_downloaded_is_unavailable_not_clean(store: FeedStore) -> None:
    feed = ListFeed(PHISH, store, now=lambda: NOW)
    with pytest.raises(ProviderUnavailable):
        lookup(feed, "http://x.test/")
    out = run(Intel([feed]).query(Subject.from_parsed(parse_url("http://x.test/"))))  # type: ignore[arg-type]
    assert out.results[0].result.status is ProviderStatus.UNAVAILABLE
    assert out.results[0].result.state is None


def test_a_stale_list_is_unavailable_not_clean(store: FeedStore) -> None:
    do_sync(store, ok_server(["http://evil-site.test/a"]), now=NOW)
    later = NOW + timedelta(seconds=PHISH.stale_after + 60)
    feed = ListFeed(PHISH, store, now=lambda: later)
    with pytest.raises(ProviderUnavailable, match="old"):
        lookup(
            feed, "http://evil-site.test/a"
        )  # even a listed URL: the list cannot be trusted as current


def test_an_unavailable_feed_does_not_trip_the_breaker(store: FeedStore) -> None:
    intel = Intel([ListFeed(PHISH, store, now=lambda: NOW)])
    subject = Subject.from_parsed(parse_url("http://x.test/"))  # type: ignore[arg-type]
    for _ in range(10):
        run(intel.query(subject))
    assert intel.health()[0]["breaker"] == "closed"


# ---- sync ----------------------------------------------------------------------------------------


def test_sync_stores_the_list_and_remembers_how_to_ask_again(store: FeedStore) -> None:
    urls = ["http://a.test/1", "http://b.test/2", "ftp://skip.test/3", "garbage"]
    server = ok_server(urls, etag='"v1"', **{"last-modified": "Wed, 04 Nov 2026 10:00:00 GMT"})
    out = do_sync(store, server)
    assert out == SyncOutcome("phishtank", "updated", 2, "ok")
    index = store.load("phishtank")
    assert index and index.meta.etag == '"v1"' and index.meta.source == "data.phishtank.com"
    assert index.meta.fetched_at == NOW and len(index.meta.sha256) == 64


def test_a_recent_list_is_not_downloaded_again(store: FeedStore) -> None:
    do_sync(store, ok_server(["http://a.test/1"]))
    server = ok_server(["http://other.test/"])
    out = do_sync(store, server, now=NOW + timedelta(minutes=10))
    assert out.status == "fresh" and server.requests == []
    assert do_sync(store, server, now=NOW + timedelta(minutes=10), force=True).status == "updated"


def test_not_modified_keeps_the_list_and_refreshes_its_age(store: FeedStore) -> None:
    do_sync(store, ok_server(["http://a.test/1"], etag='"v1"'))
    server = Server(httpx.Response(304))
    later = NOW + timedelta(hours=3)
    out = do_sync(store, server, now=later)
    assert out.status == "not_modified" and server.requests[0].headers["if-none-match"] == '"v1"'
    index = store.load("phishtank")
    assert index and index.meta.fetched_at == later and len(index.urls) == 1


FAILURES: dict[str, Callable[[httpx.Request], httpx.Response]] = {
    "500": lambda r: httpx.Response(500),
    "429": lambda r: httpx.Response(429, headers={"retry-after": "30"}),
    "401": lambda r: httpx.Response(401),
    "html": lambda r: httpx.Response(200, content=b"<html>login</html>"),
    "bad-bz2": lambda r: httpx.Response(200, content=b"BZh9" + b"\x00" * 100),
    "bad-json": lambda r: httpx.Response(200, content=bz2.compress(b"{broken")),
    "empty-list": lambda r: httpx.Response(200, content=bz2.compress(b"[]")),
    "no-http-urls": lambda r: httpx.Response(200, content=phishtank_file(["ftp://a.test/", "x"])),
}


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_a_bad_download_keeps_the_previous_list(store: FeedStore, name: str) -> None:
    do_sync(store, ok_server(["http://a.test/1", "http://b.test/2"]))
    out = do_sync(store, Server(FAILURES[name]), now=NOW + timedelta(hours=2))
    assert out.status == "error" and out.entries == 0
    index = store.load("phishtank")
    assert index and len(index.urls) == 2 and index.meta.fetched_at == NOW


def test_network_faults_are_stated_and_keep_the_list(store: FeedStore) -> None:
    do_sync(store, ok_server(["http://a.test/1"]))
    for fault in (
        httpx.ReadTimeout("slow"),
        httpx.ConnectError("refused"),
        httpx.DecodingError("bad"),
    ):

        def raise_it(_r: httpx.Request, fault: Exception = fault) -> httpx.Response:
            raise fault

        out = do_sync(store, Server(raise_it), now=NOW + timedelta(hours=2))
        assert out.status == "error" and len(store.load("phishtank").urls) == 1  # type: ignore[union-attr]


def test_a_download_over_the_size_limit_is_refused(store: FeedStore) -> None:
    small = replace(PHISH, max_download=1000)
    big = Server(httpx.Response(200, content=b"x" * 5000))
    assert do_sync(store, big, small).detail == "response too large"
    declared = Server(httpx.Response(200, content=b"x", headers={"content-length": "999999"}))
    assert do_sync(store, declared, small).detail == "response too large"


def test_a_decompression_bomb_is_refused(store: FeedStore) -> None:
    small = replace(PHISH, max_expanded=1024 * 1024)
    bomb = Server(httpx.Response(200, content=bz2.compress(b"[" + b" " * (5 * 1024 * 1024))))
    out = do_sync(store, bomb, small)
    assert out.status == "error" and "expands" in out.detail and store.load("phishtank") is None


def test_a_list_that_shrinks_to_a_fraction_is_not_trusted(store: FeedStore) -> None:
    many = [f"http://site{i}.test/p" for i in range(1500)]
    do_sync(store, ok_server(many))
    out = do_sync(store, ok_server(many[:100]), now=NOW + timedelta(hours=2))
    assert out.status == "error" and "shrank" in out.detail
    assert len(store.load("phishtank").urls) == 1500  # type: ignore[union-attr]
    assert do_sync(store, ok_server(many[:1200]), now=NOW + timedelta(hours=3)).status == "updated"


def test_redirects_are_followed_only_to_allowed_https_hosts(store: FeedStore) -> None:
    def hop(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.phishtank.com":
            return httpx.Response(302, headers={"location": "https://cdn.phishtank.com/f.bz2"})
        return httpx.Response(200, content=phishtank_file(["http://a.test/1"]))

    server = Server(hop)
    assert do_sync(store, server).status == "updated"
    assert [r.url.host for r in server.requests] == ["data.phishtank.com", "cdn.phishtank.com"]

    for target in ("https://evil.example.net/f.bz2", "http://data.phishtank.com/f.bz2",
                   "https://phishtank.com.evil.example/f"):  # fmt: skip
        server = Server(lambda r, t=target: httpx.Response(302, headers={"location": t}))
        out = do_sync(store, server, force=True)
        assert out.status == "error" and "not allowed" in out.detail, target
        assert len(server.requests) == 1  # the unallowed target was never contacted


def test_a_redirect_loop_stops(store: FeedStore) -> None:
    server = Server(
        lambda r: httpx.Response(302, headers={"location": "https://data.phishtank.com/again"})
    )
    out = do_sync(store, server)
    assert out.detail == "too many redirects" and len(server.requests) == 4


def test_a_key_goes_in_the_download_url_and_nowhere_else(
    store: FeedStore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server = ok_server(["http://a.test/1"])
    do_sync(store, server, key=KEY)
    assert (
        str(server.requests[0].url)
        == f"https://data.phishtank.com/data/{KEY}/online-valid.json.bz2"
    )
    assert KEY not in store.path("phishtank").read_text(encoding="utf-8") and KEY not in caplog.text
    for fault in (httpx.ConnectError(f"refused https://x/{KEY}/f"), httpx.ReadTimeout(KEY)):

        def raise_it(_r: httpx.Request, fault: Exception = fault) -> httpx.Response:
            raise fault

        out = do_sync(store, Server(raise_it), key=KEY, now=NOW + timedelta(hours=2))
        assert KEY not in repr(out) and KEY not in caplog.text
    failing = do_sync(store, Server(httpx.Response(500)), key=KEY, now=NOW + timedelta(hours=4))
    assert KEY not in repr(failing)


def test_without_a_key_phishtank_uses_its_keyless_url_and_urlhaus_refuses_to_start(
    store: FeedStore,
) -> None:
    server = ok_server(["http://a.test/1"])
    do_sync(store, server)
    assert str(server.requests[0].url) == "https://data.phishtank.com/data/online-valid.json.bz2"
    nothing = Server(httpx.Response(200))
    out = do_sync(store, nothing, FEEDS["urlhaus"])
    assert out.status == "error" and "key" in out.detail and nothing.requests == []


def test_openphish_and_urlhaus_sync_end_to_end(store: FeedStore) -> None:
    server = Server(
        httpx.Response(200, content=b"http://phish-one.test/a\nhttp://phish-two.test/b\n")
    )
    assert do_sync(store, server, FEEDS["openphish"]).entries == 2
    csv = b"# id,dateadded,url,url_status\n1,2026-11-01,http://m.test/a,online\n"
    out = do_sync(store, Server(httpx.Response(200, content=csv)), FEEDS["urlhaus"], key="k")
    assert out.entries == 1
    feed = ListFeed(FEEDS["urlhaus"], store, now=lambda: NOW)
    assert lookup(feed, "http://m.test/a").state is VerdictState.MALICIOUS
