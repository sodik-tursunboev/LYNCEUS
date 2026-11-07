"""urlscan.io as a provider, against a mock transport (its result endpoint was never run live).

What matters most is what is *sent*: one public registered domain in the search, a scan id taken
from the reply in the second request, the key only in a header."""

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from core.contracts import VerdictState
from core.intel.base import ProviderError, ProviderRateLimited, Query
from core.intel.http import make_client
from core.intel.urlscan import UrlScan
from rules.intel.data import scoring

KEY = "URLSCAN-KEY-SECRET-999"
SCAN = "01a1b70e-343d-73eb-91b3-91f595b60ff0"


def search_reply(*ids: str) -> dict[str, Any]:
    return {"results": [{"_id": i, "page": {"domain": "x"}} for i in ids], "total": len(ids)}


def result_reply(malicious: bool = False, score: int = 0, **extra: Any) -> dict[str, Any]:
    overall = {"malicious": malicious, "score": score, "categories": [], "brands": [], **extra}
    return {"verdicts": {"overall": overall}, "task": {"time": "2026-11-07T17:28:57.762Z"}}


class Server:
    def __init__(self, routes: Callable[[httpx.Request], httpx.Response]) -> None:
        self.routes, self.requests = routes, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.routes(request)

    @property
    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]


def ask(
    search: Any, result: Any = None, status: int = 200, name: str = "badsite.com"
) -> tuple[Any, Server]:
    def routes(request: httpx.Request) -> httpx.Response:
        body = search if "/search/" in request.url.path else result
        if isinstance(body, bytes):
            return httpx.Response(status, content=body)
        return httpx.Response(status, json=body)

    server = Server(routes)
    provider = UrlScan(make_client(httpx.MockTransport(server)), KEY)
    try:
        return asyncio.run(provider.lookup(Query(name=name))), server
    finally:
        asyncio.run(provider.aclose())


def test_a_malicious_verdict_is_reported_with_its_categories() -> None:
    reply = result_reply(True, 100, categories=["phishing"], brands=["PayPal"])
    a, _ = ask(search_reply(SCAN), reply)
    assert a.state is VerdictState.MALICIOUS and a.facts["urlscan"] == "malicious"
    assert "phishing" in (a.detail or "") and "paypal" in (a.detail or "")
    assert "scanned 2026-11-07" in a.provenance


def test_a_high_score_without_the_malicious_flag_is_suspicious() -> None:
    a, _ = ask(search_reply(SCAN), result_reply(False, 60))
    assert a.state is VerdictState.SUSPICIOUS and a.facts["urlscan"] == "suspicious"


def test_a_scan_without_a_malicious_verdict_proves_nothing() -> None:
    a, _ = ask(search_reply(SCAN), result_reply(False, 0))
    assert a.state is VerdictState.UNKNOWN and "urlscan" not in a.facts


def test_a_domain_nobody_scanned_is_unknown_and_costs_one_request() -> None:
    a, server = ask(search_reply())
    assert a.state is VerdictState.UNKNOWN and len(server.requests) == 1


def test_only_the_domain_is_sent_and_the_key_only_in_a_header() -> None:
    _, server = ask(search_reply(SCAN), result_reply())
    first, second = server.requests
    assert first.url.host == second.url.host == "urlscan.io"
    assert (
        first.url.path == "/api/v1/search/"
        and dict(first.url.params)["q"] == "page.apexDomain:badsite.com"
    )
    assert second.url.path == f"/api/v1/result/{SCAN}/" and not second.url.query
    for r in server.requests:
        assert r.method == "GET" and r.headers["API-Key"] == KEY and r.content == b""
        assert KEY not in str(r.url)
    assert KEY not in repr(UrlScan(make_client(), KEY))


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "x", SCAN + "/extra", "", "01A1B70E-343D"])
def test_a_scan_id_that_is_not_a_uuid_is_never_requested(bad_id: str) -> None:
    with pytest.raises(ProviderError):
        ask(search_reply(bad_id), result_reply())


@pytest.mark.parametrize(
    "garbage",
    [b"not json", b"[]", b'{"results": "x"}', json.dumps({"results": [{"no": "id"}]}).encode()],
)
def test_a_search_reply_of_the_wrong_shape_is_an_error_not_a_verdict(garbage: bytes) -> None:
    with pytest.raises(ProviderError):
        ask(garbage)


@pytest.mark.parametrize("garbage", [b"nope", b"{}", json.dumps({"verdicts": {}}).encode()])
def test_a_result_reply_of_the_wrong_shape_is_an_error_not_a_verdict(garbage: bytes) -> None:
    with pytest.raises(ProviderError):
        ask(search_reply(SCAN), garbage)


def test_a_rate_limit_is_reported_as_one() -> None:
    with pytest.raises(ProviderRateLimited):
        ask({"message": "slow down"}, status=429)


def test_a_server_error_is_an_error_not_a_clean_answer() -> None:
    with pytest.raises(ProviderError):
        ask({"message": "boom"}, status=500)


def test_words_from_the_service_are_filtered_before_they_reach_the_explanation() -> None:
    nasty = "phishing\n<script>alert(1)</script>"
    a, _ = ask(search_reply(SCAN), result_reply(True, 100, categories=[nasty, "malware"]))
    assert "<" not in (a.detail or "") and "malware" in (a.detail or "")


def test_no_name_means_nothing_is_sent() -> None:
    server = Server(lambda _r: httpx.Response(200, json={}))
    provider = UrlScan(make_client(httpx.MockTransport(server)), KEY)
    with pytest.raises(ProviderError):
        asyncio.run(provider.lookup(Query(name=None, host="x.local")))
    assert server.requests == []


def test_both_findings_have_a_configured_weight_and_the_category_a_cap() -> None:
    cfg = scoring()
    assert {"intel.urlscan.malicious", "intel.urlscan.suspicious"} <= set(cfg["weights"])
    assert "intel.urlscan" in cfg["category_caps"]
