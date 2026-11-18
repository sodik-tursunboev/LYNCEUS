"""DA2: the file lookup at VirusTotal, against a mock transport. What matters most is what is SENT:
the hash and the key header, nothing else; and that a failure is no answer, never a verdict."""

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from core.intel.base import ProviderError, ProviderRateLimited
from core.intel.filerep import BASE, FileReputation
from core.intel.http import make_client

KEY = "VT-FILE-KEY-SECRET-777"  # pragma: allowlist secret
SHA = "ab" * 32


class Server:
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler, self.requests = handler, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    def client(self) -> httpx.AsyncClient:
        return make_client(httpx.MockTransport(self))


def reply(malicious: int, date: int | None = 1793000000) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 1, "harmless": 0,
                                "undetected": 60, "timeout": 2, "type-unsupported": 3},
        "meaningful_name": "must-not-matter.exe",
    }  # fmt: skip
    if date is not None:
        attrs["last_analysis_date"] = date
    return {"data": {"id": SHA, "type": "file", "attributes": attrs}}


def make(server: Server, clock: Callable[[], float] | None = None) -> FileReputation:
    return FileReputation(server.client(), KEY, **({"clock": clock} if clock else {}))


def ask(rep: FileReputation, sha: str = SHA) -> Any:
    return asyncio.run(rep.lookup(sha))


def test_the_request_is_the_hash_and_the_key_header_only() -> None:
    server = Server(lambda r: httpx.Response(200, json=reply(12)))
    rep = ask(make(server))
    (request,) = server.requests
    assert str(request.url) == BASE + SHA and request.method == "GET"
    assert request.headers["x-apikey"] == KEY and request.url.query == b"" and not request.content
    assert KEY not in str(request.url)
    assert (rep.malicious, rep.engines) == (
        12,
        12 + 1 + 0 + 60,
    )  # timeouts and unsupported left out
    assert rep.analysed is not None and rep.analysed.year == 2026


def test_the_key_is_not_in_the_answer_the_repr_or_the_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    r = make(Server(lambda r: httpx.Response(200, json=reply(3))))
    rep = ask(r)
    assert KEY not in repr(r) and KEY not in repr(rep) and KEY not in caplog.text
    server = Server(lambda r: httpx.Response(401))
    caplog.clear()
    assert asyncio.run(make(server).ask(SHA)) == (None, "failed")
    assert KEY not in caplog.text


def test_a_hash_is_asked_once_while_the_answer_is_fresh() -> None:
    now = [0.0]
    server = Server(lambda r: httpx.Response(200, json=reply(1)))
    r = make(server, clock=lambda: now[0])
    ask(r), ask(r)
    assert len(server.requests) == 1
    now[0] += 6 * 3600 + 1
    ask(r)
    assert len(server.requests) == 2


def test_no_report_is_remembered_for_an_hour_and_is_not_an_error() -> None:
    now = [0.0]
    server = Server(lambda r: httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    r = make(server, clock=lambda: now[0])
    assert ask(r) is None and ask(r) is None and len(server.requests) == 1
    now[0] += 3601
    assert ask(r) is None and len(server.requests) == 2
    assert asyncio.run(r.ask(SHA)) == (None, "no_report")


def test_a_rate_limit_pauses_further_questions() -> None:
    now = [0.0]
    server = Server(lambda r: httpx.Response(429, json={"error": {"code": "QuotaExceededError"}}))
    r = make(server, clock=lambda: now[0])
    with pytest.raises(ProviderRateLimited):
        ask(r)
    with pytest.raises(ProviderRateLimited):
        ask(r, "cd" * 32)  # paused: not even asked
    assert len(server.requests) == 1
    assert asyncio.run(r.ask("ef" * 32)) == (None, "failed")


def test_four_a_minute_and_no_more() -> None:
    now = [0.0]
    server = Server(lambda r: httpx.Response(404))
    r = make(server, clock=lambda: now[0])
    for i in range(4):
        ask(r, f"{i:02x}" * 32)
    with pytest.raises(ProviderRateLimited):
        ask(r, "99" * 32)
    now[0] += 61
    ask(r, "99" * 32)
    assert len(server.requests) == 5


@pytest.mark.parametrize(
    "body",
    [b"not json", b"{}", b'{"data": {}}', b'{"data":{"attributes":{}}}',
     b'{"data":{"attributes":{"last_analysis_stats":{"malicious":-1}}}}',
     b'{"data":{"attributes":{"last_analysis_stats":{"malicious":99999}}}}'],
)  # fmt: skip
def test_a_malformed_reply_is_no_answer(body: bytes) -> None:
    r = make(Server(lambda r: httpx.Response(200, content=body)))
    with pytest.raises(ProviderError):
        ask(r)
    assert asyncio.run(make(Server(lambda r: httpx.Response(200, content=body))).ask(SHA)) == (
        None,
        "failed",
    )


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_a_refused_key_or_a_server_error_is_no_answer_never_a_clean_file(status: int) -> None:
    out = asyncio.run(make(Server(lambda r: httpx.Response(status))).ask(SHA))
    assert out == (None, "failed")


@pytest.mark.parametrize("bad", ["", "zz", "A" * 10, "g" * 64, "1" * 63, "../etc/passwd"])
def test_only_a_sha256_is_ever_put_in_a_request(bad: str) -> None:
    server = Server(lambda r: httpx.Response(200, json=reply(1)))
    with pytest.raises(ProviderError):
        ask(make(server), bad)
    assert server.requests == []


def test_a_slow_answer_is_given_up_on() -> None:
    async def slow() -> Any:
        r = make(Server(lambda r: httpx.Response(200, json=reply(1))))

        async def never(_sha: str) -> Any:
            await asyncio.sleep(60)

        r.lookup = never  # type: ignore[method-assign]
        import core.intel.filerep as module

        original = module.WAIT
        module.WAIT = 0.05
        try:
            return await r.ask(SHA)
        finally:
            module.WAIT = original

    assert asyncio.run(slow()) == (None, "failed")
