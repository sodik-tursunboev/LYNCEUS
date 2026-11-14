"""The two providers that ask an outside service (RDAP, VirusTotal), against a mock transport.

What matters most is what is *sent*: every request is captured and checked, end to end through the
egress gate, for anything beyond one public registered domain."""

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from core.contracts import ProviderStatus, VerdictState
from core.intel.analyze import analyze_with_intel
from core.intel.base import ProviderError, ProviderRateLimited, ProviderUnavailable, Query
from core.intel.http import make_client
from core.intel.orchestrator import Intel
from core.intel.rdap import BOOTSTRAP_URL, Rdap, parse_bootstrap
from core.intel.virustotal import MANY, VirusTotal
from rules.intel.data import scoring

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
KEY = "VT-KEY-SECRET-999"
REGISTRY = "https://rdap.registry.example.com/v1/"
BOOTSTRAP = {
    "version": "1.0",
    "publication": "2026-10-28T00:00:00Z",
    "services": [
        [["com", "net"], [REGISTRY]],
        [["uk"], ["https://rdap.uk.example.org/"]],
        [["co.uk"], ["https://rdap.couk.example.org/"]],
        [["org"], ["http://insecure.example.org/"]],  # not https: refused
        [["xyz"], ["https://203.0.113.5/"]],  # an IP literal: refused
        # credentials in the URL: refused
        [["dev"], ["https://user:pw@rdap.example.com/"]],  # pragma: allowlist secret
        [["app"], ["https://localhost/"]],  # not a public name: refused
        [["io"], ["https://rdap.example.com:8443/"]],  # odd port: refused
    ],
}


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class Server:
    def __init__(self, routes: Callable[[httpx.Request], httpx.Response]) -> None:
        self.routes, self.requests = routes, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.routes(request)

    def client(self) -> httpx.AsyncClient:
        return make_client(httpx.MockTransport(self))

    @property
    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]


def rdap_reply(days_old: int | None, action: str = "registration") -> dict[str, Any]:
    events: list[dict[str, str]] = [
        {"eventAction": "last changed", "eventDate": "2026-10-01T00:00:00Z"}
    ]
    if days_old is not None:
        when = datetime.fromordinal(NOW.toordinal() - days_old).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append({"eventAction": action, "eventDate": when})
    return {"objectClassName": "domain", "ldhName": "x", "events": events}


def rdap_server(reply: Any = None, status: int = 200) -> Server:
    def routes(request: httpx.Request) -> httpx.Response:
        if str(request.url) == BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        if isinstance(reply, bytes):
            return httpx.Response(status, content=reply)
        return httpx.Response(status, json=reply if reply is not None else rdap_reply(5))

    return Server(routes)


REGISTRY_IP = "93.184.215.14"  # a public address the fake resolver gives every registry name


async def public_resolver(host: str) -> list[str]:
    return [REGISTRY_IP]


def ask_rdap(server: Server, name: str = "newshop.com", **kw: Any) -> Any:
    kw.setdefault("resolve", public_resolver)
    rdap = Rdap(server.client(), now=lambda: NOW, **kw)
    return run(rdap.lookup(Query(name=name)))


# ---- RDAP ----------------------------------------------------------------------------------------


def test_a_young_domain_is_reported_with_its_age() -> None:
    a = ask_rdap(rdap_server(rdap_reply(5)))
    assert a.state is VerdictState.SUSPICIOUS and a.facts == {"age_days": 5}
    assert a.detail == "registered 5 days ago" and "rdap.registry.example.com" in a.provenance


@pytest.mark.parametrize(
    ("days", "state"), [(0, "SUSPICIOUS"), (29, "SUSPICIOUS"), (30, "UNKNOWN"), (4000, "UNKNOWN")]
)
def test_age_bands_in_the_answers_own_state(days: int, state: str) -> None:
    a = ask_rdap(rdap_server(rdap_reply(days)))
    assert a.state.value == state and a.facts == {"age_days": days}


def test_an_old_domain_is_not_called_safe() -> None:
    assert ask_rdap(rdap_server(rdap_reply(6000))).state is VerdictState.UNKNOWN


@pytest.mark.parametrize(
    "reply",
    [
        rdap_reply(None),
        {"events": []},
        {"events": "nope"},
        {"events": [{"eventAction": "registration"}]},
        {"events": [{"eventAction": "registration", "eventDate": "not a date"}]},
        {"events": [{"eventAction": "registration", "eventDate": 12345}]},
        ["not", "an", "object"],
        {},
    ],
)
def test_a_missing_or_odd_registration_date_is_no_answer_not_an_old_domain(reply: Any) -> None:
    a = ask_rdap(rdap_server(reply))
    assert a.state is VerdictState.UNKNOWN and a.facts == {}


def test_a_date_without_a_timezone_and_odd_capitalisation_still_parse() -> None:
    reply = {"events": [{"eventAction": "Registration", "eventDate": "2026-10-31T12:00:00"}]}
    assert ask_rdap(rdap_server(reply)).facts == {"age_days": 5}


def test_a_registration_date_in_the_future_is_ignored() -> None:
    reply = {"events": [{"eventAction": "registration", "eventDate": "2027-01-01T00:00:00Z"}]}
    a = ask_rdap(rdap_server(reply))
    assert a.facts == {} and "future" in (a.detail or "")


def test_an_unknown_domain_is_no_answer() -> None:
    a = ask_rdap(rdap_server({"errorCode": 404}, status=404))
    assert a.state is VerdictState.UNKNOWN and a.facts == {}


@pytest.mark.parametrize("status", [500, 503, 401, 403, 302])
def test_a_registry_error_is_a_provider_error(status: int) -> None:
    with pytest.raises(ProviderError):
        ask_rdap(rdap_server({}, status=status))


def test_a_429_is_a_rate_limit_not_an_error() -> None:
    def routes(request: httpx.Request) -> httpx.Response:
        if str(request.url) == BOOTSTRAP_URL:
            return httpx.Response(200, json=BOOTSTRAP)
        return httpx.Response(429, headers={"retry-after": "45"})

    with pytest.raises(ProviderRateLimited) as info:
        ask_rdap(Server(routes))
    assert info.value.retry_after == 45


@pytest.mark.parametrize("body", [b"not json", b"{" * 100_000, b""])
def test_a_reply_that_is_not_json_is_a_provider_error(body: bytes) -> None:
    with pytest.raises(ProviderError):
        ask_rdap(rdap_server(body))


def test_an_oversize_reply_is_refused() -> None:
    with pytest.raises(ProviderError, match="too large"):
        ask_rdap(rdap_server(b"x" * (300 * 1024)))


def test_the_query_is_one_domain_name_with_no_credentials_and_no_query_string() -> None:
    server = rdap_server()
    ask_rdap(server, "newshop.com")
    assert server.urls == [BOOTSTRAP_URL, f"https://{REGISTRY_IP}/v1/domain/newshop.com"]
    query = server.requests[1]
    assert query.headers["accept"] == "application/rdap+json"
    assert query.headers["host"] == "rdap.registry.example.com"  # the name, for Host and TLS only
    assert query.extensions["sni_hostname"] == "rdap.registry.example.com"
    assert "x-apikey" not in query.headers and "authorization" not in query.headers


def test_the_bootstrap_is_fetched_once_and_again_after_it_expires() -> None:
    server = rdap_server()
    now = [1000.0]
    rdap = Rdap(server.client(), now=lambda: NOW, clock=lambda: now[0], resolve=public_resolver)

    async def go() -> tuple[int, int]:
        for _ in range(3):
            await rdap.lookup(Query(name="newshop.com"))
        before = server.urls.count(BOOTSTRAP_URL)
        now[0] += 25 * 3600  # past the 24 h lifetime of the bootstrap file
        await rdap.lookup(Query(name="newshop.com"))
        return before, server.urls.count(BOOTSTRAP_URL)

    assert run(go()) == (1, 2)


def test_the_longest_matching_suffix_picks_the_server() -> None:
    server = rdap_server()
    ask_rdap(server, "shop.co.uk")
    assert server.urls[-1].endswith("/domain/shop.co.uk")
    assert server.requests[-1].headers["host"] == "rdap.couk.example.org"
    server = rdap_server()
    ask_rdap(server, "shop.uk")
    assert server.requests[-1].headers["host"] == "rdap.uk.example.org"


def test_a_top_level_domain_with_no_server_is_unavailable_not_clean() -> None:
    with pytest.raises(ProviderUnavailable):
        ask_rdap(rdap_server(), "shop.invalidtld")


def test_one_malformed_bootstrap_entry_is_skipped_and_does_not_break_the_others() -> None:
    odd = {
        "version": "1.0",
        "services": [
            [["bad"], ["https://x.example.com:abc/"]],  # a port that is not a number
            [["worse"], ["https://[::1/"]],  # an unclosed bracket
            [["com"], ["https://rdap.registry.example.com/v1/"]],
        ],
    }
    assert parse_bootstrap(json.dumps(odd).encode()) == {
        "com": "https://rdap.registry.example.com/v1/"
    }


def test_unsafe_servers_in_the_bootstrap_file_are_never_used() -> None:
    table = parse_bootstrap(json.dumps(BOOTSTRAP).encode())
    assert set(table) == {"com", "net", "uk", "co.uk"}
    for tld in ("org", "xyz", "dev", "app", "io"):
        with pytest.raises(ProviderUnavailable):
            ask_rdap(rdap_server(), f"shop.{tld}")


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[]", b'{"services": "x"}', b'{"services": []}', b'{"services": [[1, 2]]}'],
)
def test_a_broken_bootstrap_file_is_a_provider_error(raw: bytes) -> None:
    with pytest.raises(ProviderError):
        parse_bootstrap(raw)
    server = Server(lambda r: httpx.Response(200, content=raw))
    with pytest.raises(ProviderError):
        ask_rdap(server)


def test_an_unreachable_bootstrap_is_a_provider_error() -> None:
    with pytest.raises(ProviderError):
        ask_rdap(Server(lambda r: httpx.Response(503)))


# ---- VirusTotal ----------------------------------------------------------------------------------


def vt_reply(
    malicious: int, suspicious: int = 0, harmless: int = 60, date: int | None = 1793000000
) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                 "harmless": harmless, "undetected": 10, "timeout": 0},
        "reputation": -5, "categories": {"x": "phishing"},
    }  # fmt: skip
    if date is not None:
        attrs["last_analysis_date"] = date
    return {"data": {"id": "newshop.com", "type": "domain", "attributes": attrs}}


def ask_vt(server: Server, name: str = "newshop.com") -> Any:
    vt = VirusTotal(server.client(), KEY, now=lambda: NOW)
    return run(vt.lookup(Query(name=name)))


@pytest.mark.parametrize(
    ("malicious", "state", "words"),
    [
        (0, "UNKNOWN", "proves nothing"),
        (1, "SUSPICIOUS", "1 engine(s)"),
        (2, "SUSPICIOUS", "2 engine(s)"),
        (MANY, "MALICIOUS", "flag this domain"),
        (40, "MALICIOUS", "flag this domain"),
    ],
)
def test_detection_counts_become_an_opinion_but_never_benign(
    malicious: int, state: str, words: str
) -> None:
    a = ask_vt(Server(lambda r: httpx.Response(200, json=vt_reply(malicious, harmless=70))))
    assert a.state.value == state and words in a.detail
    assert a.facts["detections"] == malicious and a.facts["harmless"] == 70


def test_the_provider_count_matches_the_scoring_config() -> None:
    assert scoring()["thresholds"]["vt_many"] == MANY


def test_the_key_travels_in_a_header_and_the_url_is_just_the_domain() -> None:
    server = Server(lambda r: httpx.Response(200, json=vt_reply(0)))
    ask_vt(server)
    (request,) = server.requests
    assert str(request.url) == "https://www.virustotal.com/api/v3/domains/newshop.com"
    assert request.headers["x-apikey"] == KEY and request.url.query == b""
    assert KEY not in str(request.url) and request.method == "GET" and not request.content


def test_the_key_is_not_in_the_answer_the_repr_or_the_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    server = Server(lambda r: httpx.Response(200, json=vt_reply(5)))
    vt = VirusTotal(server.client(), KEY, now=lambda: NOW)
    answer = run(vt.lookup(Query(name="newshop.com")))
    assert KEY not in repr(vt) and KEY not in repr(answer) and KEY not in caplog.text


def test_the_analysis_date_is_part_of_the_provenance() -> None:
    a = ask_vt(Server(lambda r: httpx.Response(200, json=vt_reply(0, date=1793000000))))
    assert "analysed 2026-10-26" in a.provenance
    b = ask_vt(Server(lambda r: httpx.Response(200, json=vt_reply(0, date=None))))
    assert "analysed" not in b.provenance


def test_no_report_is_no_answer() -> None:
    a = ask_vt(Server(lambda r: httpx.Response(404, json={"error": {"code": "NotFoundError"}})))
    assert a.state is VerdictState.UNKNOWN and a.facts == {}


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credentials_are_a_stated_error(status: int) -> None:
    with pytest.raises(ProviderError, match="credentials rejected"):
        ask_vt(
            Server(
                lambda r: httpx.Response(status, json={"error": {"code": "WrongCredentialsError"}})
            )
        )


@pytest.mark.parametrize("status", [500, 503])
def test_a_server_error_is_a_provider_error(status: int) -> None:
    with pytest.raises(ProviderError):
        ask_vt(Server(lambda r: httpx.Response(status)))


def test_a_minute_quota_pauses_briefly_and_a_daily_quota_until_the_utc_reset() -> None:
    minute = {
        "error": {
            "code": "QuotaExceededError",
            "message": "You have exceeded one of your quotas (minute).",
        }
    }
    daily = {
        "error": {"code": "QuotaExceededError", "message": "You have exceeded your daily quota."}
    }
    with pytest.raises(ProviderRateLimited) as short:
        ask_vt(Server(lambda r: httpx.Response(429, json=minute)))
    assert short.value.retry_after is None
    with pytest.raises(ProviderRateLimited) as long:
        ask_vt(Server(lambda r: httpx.Response(429, json=daily)))
    assert long.value.retry_after == 12 * 3600  # NOW is noon UTC


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        b'{"data": {}}',
        b'{"data": {"attributes": {}}}',
        b'{"data": {"attributes": {"last_analysis_stats": {"malicious": -1}}}}',
        b'{"data": {"attributes": {"last_analysis_stats": {"malicious": "many"}}}}',
        b'{"data": {"attributes": {"last_analysis_stats": {"malicious": 99999}}}}',
        b'{"data":{"attributes":{"last_analysis_stats":{"malicious":1},"last_analysis_date":-1}}}',
    ],
)
def test_an_unexpected_reply_shape_is_a_provider_error(body: bytes) -> None:
    with pytest.raises(ProviderError):
        ask_vt(Server(lambda r: httpx.Response(200, content=body)))


def test_extra_fields_in_the_reply_are_ignored() -> None:
    reply = vt_reply(1)
    reply["data"]["attributes"]["surprise"] = {"deep": [1, 2, 3]}
    assert ask_vt(Server(lambda r: httpx.Response(200, json=reply))).facts["detections"] == 1


# ---- end to end: what actually leaves the machine ------------------------------------------------


def both(server: Server) -> Intel:
    client = server.client()
    return Intel(
        [
            Rdap(client, now=lambda: NOW, resolve=public_resolver),
            VirusTotal(client, KEY, now=lambda: NOW),
        ],
        email_links=False,
    )


def world(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url == BOOTSTRAP_URL:
        return httpx.Response(200, json=BOOTSTRAP)
    if request.headers["host"] == "rdap.registry.example.com":
        return httpx.Response(200, json=rdap_reply(2))
    return httpx.Response(200, json=vt_reply(6))


SENSITIVE = (
    "https://login.shop.example.com/account/reset?token=SECRET-TOKEN-42&u=jane%40mail.example#frag"
)


def test_only_a_registered_domain_ever_leaves_and_the_key_stays_in_its_header() -> None:
    server = Server(world)
    analysis, outcome = run(analyze_with_intel(SENSITIVE, both(server)))
    assert len(server.requests) == 3  # bootstrap, one RDAP query, one VirusTotal query
    for request in server.requests:
        blob = str(request.url) + " " + str(dict(request.headers)) + request.content.decode()
        for private in ("SECRET-TOKEN-42", "reset", "jane", "frag", "login.shop", "account"):
            assert private not in blob, (private, str(request.url))
    assert server.urls[1].endswith("/domain/example.com")
    assert server.urls[2] == "https://www.virustotal.com/api/v3/domains/example.com"
    assert [r.result.status for r in outcome.results] == [ProviderStatus.OK] * 2


def test_a_young_flagged_domain_is_malicious_through_the_whole_pipeline() -> None:
    analysis, _ = run(analyze_with_intel("https://www.example.com/page", both(Server(world))))
    v = analysis.verdict
    assert v.state is VerdictState.MALICIOUS and v.confidence.value in ("MEDIUM", "HIGH")
    assert {s.rule_id for s in v.signals} == {
        "intel.domain_age.week",
        "intel.virustotal.detections_many",
    }
    assert [p.provider for p in v.provider_results] == ["rdap", "virustotal"]


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal-login.test/signin",  # the synthetic corpus
        "https://203.0.113.5/login",  # an IP address
        "http://localhost:8080/admin",
        "https://intranet/hr/salaries",
        "https://printer.local/",
        "javascript:alert(1)",
    ],
)
def test_names_that_are_not_public_send_nothing_at_all(url: str) -> None:
    server = Server(world)
    run(analyze_with_intel(url, both(server)))
    assert server.requests == []


def test_message_links_send_nothing_unless_the_operator_allows_it() -> None:
    from core.intel.analyze import link_analyzer

    server = Server(world)
    link_analyzer(both(server))("https://www.example.com/page")
    assert server.requests == []
    client = server.client()
    allowed = Intel([Rdap(client, now=lambda: NOW, resolve=public_resolver)], email_links=True)
    link_analyzer(allowed)("https://www.example.com/page")
    assert len(server.requests) == 2


def test_a_dead_internet_still_returns_the_local_verdict() -> None:
    def down(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to https://www.virustotal.com/?key=" + KEY)

    server = Server(down)
    analysis, outcome = run(
        analyze_with_intel("https://paypal.com@secure-check.test/login.php", both(server))
    )
    assert analysis.verdict.state in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    assert server.requests == []  # a .test host is never asked about
    live, outcome = run(analyze_with_intel("https://www.example.com/x", both(server)))
    assert live.verdict.state is VerdictState.UNKNOWN
    assert all(r.result.state is None for r in outcome.results)
    assert KEY not in repr(outcome) and KEY not in live.model_dump_json()


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["10.0.0.5"],
        ["169.254.169.254"],  # cloud metadata
        ["::1"],
        ["::ffff:192.168.1.1"],  # private IPv4 inside IPv6
        [REGISTRY_IP, "192.168.0.10"],  # one private answer among public ones is enough to refuse
        [],
    ],
)
def test_a_registry_name_that_resolves_to_a_private_address_is_never_reached(
    addresses: list[str],
) -> None:
    """H1 A3: the bootstrap file is untrusted; its server name is resolved, every address must be
    public, and the request goes to that checked address (no second resolution to race)."""

    async def resolve(host: str) -> list[str]:
        return addresses

    server = rdap_server()
    with pytest.raises(ProviderError):
        ask_rdap(server, resolve=resolve)
    assert server.urls == [BOOTSTRAP_URL]  # only the fixed IANA file was fetched


def test_a_registry_name_that_does_not_resolve_is_unavailable() -> None:
    async def resolve(host: str) -> list[str]:
        raise OSError("no such host")

    with pytest.raises(ProviderUnavailable):
        ask_rdap(rdap_server(), resolve=resolve)
