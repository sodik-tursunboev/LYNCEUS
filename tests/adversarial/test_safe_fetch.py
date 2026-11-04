"""SSRF suite. Fake DNS and fake transport only: no real sockets.

The assertions that matter are about what was never reached: `net.targets` lists every connection
attempt, so a test can show the guard stopped it before anything left the process.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from ssrf_inputs import SSRF_INPUTS

from core.config import Settings
from core.urls import safe_fetch
from core.urls.safe_fetch import (
    USER_AGENT,
    Chain,
    HttpxConnector,
    Limits,
    Outcome,
    Reply,
    Target,
    follow,
    is_public,
)

PUBLIC = "93.184.216.34"
PUBLIC_2 = "8.8.8.8"


class Net:
    """Scripted DNS and server. `dns` values are lists of answers, consumed one per lookup."""

    def __init__(self, dns: dict[str, list[list[str]]], replies: dict[str, Reply] | None = None):
        self.dns, self.replies = dns, replies or {}
        self.lookups: list[str] = []
        self.targets: list[Target] = []

    async def resolve(self, host: str) -> list[str]:
        self.lookups.append(host)
        answers = self.dns.get(host)
        if not answers:
            raise OSError("no such host")
        return answers.pop(0) if len(answers) > 1 else answers[0]

    async def connect(self, target: Target) -> Reply:
        self.targets.append(target)
        return self.replies.get(target.host + target.path_query, Reply(200, None))


def go(url: str, net: Net, limits: Limits = Limits()) -> Chain:  # noqa: B008
    return asyncio.run(
        follow(url, enabled=True, resolve=net.resolve, connect=net.connect, limits=limits)
    )


# ---- the address guard -------------------------------------------------------------------------

BLOCKED_ADDRESSES = [
    # IPv4: loopback, private, CGNAT, link-local, metadata, reserved, multicast, documentation
    "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.254",
    "100.100.100.200", "127.0.0.1", "127.255.255.254", "169.254.0.1", "169.254.169.254",
    "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.0.8", "192.0.0.192", "192.0.2.1",
    "192.168.0.1", "198.18.0.1", "198.19.255.254", "198.51.100.1", "203.0.113.1", "224.0.0.1",
    "239.255.255.250", "240.0.0.1", "255.255.255.255", "168.63.129.16",
    # IPv6: unspecified, loopback, link-local, site-local, unique-local, multicast, documentation
    "::", "::1", "fe80::1", "fe80::1%eth0", "fec0::1", "fc00::1", "fd00:ec2::254", "ff02::1",
    "ff0e::1", "2001:db8::1", "100::1",
    # IPv4 hiding inside IPv6: mapped, NAT64, IPv4-compatible, 6to4, Teredo
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1",
    "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "::127.0.0.1", "::10.0.0.1",
    "2002:7f00:1::", "2002:a00:1::", "2002:a9fe:a9fe::", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    # Not an address at all
    "not-an-ip", "", "1.2.3", "::ffff:zz",
]  # fmt: skip
ALLOWED_ADDRESSES = [
    PUBLIC, PUBLIC_2, "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
    "::ffff:8.8.8.8", "64:ff9b::808:808",
]  # fmt: skip


@pytest.mark.parametrize("address", BLOCKED_ADDRESSES)
def test_non_public_addresses_are_refused(address: str) -> None:
    assert is_public(address) is False


@pytest.mark.parametrize("address", ALLOWED_ADDRESSES)
def test_public_addresses_pass(address: str) -> None:
    assert is_public(address) is True


# ---- the probe list ----------------------------------------------------------------------------


@pytest.mark.parametrize(("url", "why"), SSRF_INPUTS)
def test_every_ssrf_probe_is_stopped(url: str, why: str) -> None:
    net = Net(
        {
            "rebind.test": [["127.0.0.1"]],
            "redirector.test": [[PUBLIC]],
            "metadata.google.internal": [["169.254.169.254"]],
        },
        {"redirector.test/to-internal": Reply(302, "http://169.254.169.254/latest/meta-data/")},
    )
    chain = go(url, net)
    assert chain.outcome is Outcome.BLOCKED, why
    assert all(is_public(t.ip) for t in net.targets), why


@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://0x7f.1/",
        "http://127.1/", "http://0177.0.0.1/", "http://%31%32%37.0.0.1/", "http://3232235777/",
        "http://[::ffff:7f00:1]/", "http://[::1]/", "http://[0:0:0:0:0:0:0:1]/",
        "http://[64:ff9b::7f00:1]/",
    ],
)  # fmt: skip
def test_numeric_host_spellings_are_read_as_the_browser_reads_them(url: str) -> None:
    net = Net({})
    assert go(url, net).outcome is Outcome.BLOCKED
    assert net.lookups == [] and net.targets == []


@pytest.mark.parametrize(
    "url",
    ["http://localhost/", "http://LOCALHOST./", "http://foo.localhost/", "http://db.internal/",
     "http://printer.local/", "http://intranet/", "http://nas.lan/"],
)  # fmt: skip
def test_internal_names_are_refused_before_any_lookup(url: str) -> None:
    net = Net({})
    assert go(url, net).outcome is Outcome.BLOCKED
    assert net.lookups == []  # not even the DNS query leaves the machine


@pytest.mark.parametrize(
    "url",
    ["http://example.test:22/", "http://example.test:6379/", "http://example.test:9200/",
     "http://example.test:8080/", "https://example.test:8443/", "http://example.test:25/"],
)  # fmt: skip
def test_ports_outside_the_policy_are_refused(url: str) -> None:
    net = Net({"example.test": [[PUBLIC]]})
    assert go(url, net).outcome is Outcome.BLOCKED
    assert net.targets == [] and net.lookups == []


@pytest.mark.parametrize(
    "url",
    ["ftp://example.test/", "file:///etc/hosts", "javascript:alert(1)", "data:text/html,x",
     "gopher://example.test/", "ws://example.test/"],
)  # fmt: skip
def test_only_http_and_https(url: str) -> None:
    net = Net({"example.test": [[PUBLIC]]})
    chain = go(url, net)
    assert chain.outcome in (Outcome.BLOCKED, Outcome.INVALID)
    assert net.targets == []


def test_credentials_in_a_url_are_refused() -> None:
    net = Net({"example.test": [[PUBLIC]]})
    assert go("https://user@example.test/", net).outcome is Outcome.BLOCKED
    assert net.targets == []


# ---- DNS -------------------------------------------------------------------------------------


def test_one_private_answer_taints_the_name() -> None:
    net = Net({"mixed.test": [[PUBLIC, "10.0.0.1"]]})
    assert go("http://mixed.test/", net).outcome is Outcome.BLOCKED
    assert net.targets == []


def test_ipv6_answer_hiding_loopback_is_refused() -> None:
    net = Net({"sly.test": [["2606:4700:4700::1111", "64:ff9b::7f00:1"]]})
    assert go("http://sly.test/", net).outcome is Outcome.BLOCKED


def test_rebinding_second_lookup_private_is_caught() -> None:
    net = Net(
        {"rebind.test": [[PUBLIC], ["127.0.0.1"]]},
        {"rebind.test/": Reply(302, "/next")},
    )
    chain = go("http://rebind.test/", net)
    assert chain.outcome is Outcome.BLOCKED
    assert [t.ip for t in net.targets] == [PUBLIC]  # the private answer was never connected to


def test_the_connector_only_ever_receives_the_validated_ip() -> None:
    net = Net(
        {"a.test": [[PUBLIC]], "b.test": [[PUBLIC_2]]}, {"a.test/": Reply(301, "http://b.test/x")}
    )
    chain = go("http://a.test/", net)
    assert chain.outcome is Outcome.COMPLETE
    assert [(t.ip, t.host) for t in net.targets] == [(PUBLIC, "a.test"), (PUBLIC_2, "b.test")]
    assert net.lookups == ["a.test", "b.test"]  # exactly one lookup per hop, none by the connector


def test_a_name_that_does_not_resolve_fails_closed() -> None:
    net = Net({})
    assert go("http://nowhere.test/", net).outcome is Outcome.FAILED
    assert net.targets == []


# ---- redirects -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
     "http://2130706433/", "http://localhost/", "http://example.test:22/", "ftp://example.test/",
     "file:///etc/hosts", "javascript:alert(1)", "http://u@example.test/"],
)  # fmt: skip
def test_redirects_are_revalidated(location: str) -> None:
    net = Net(
        {"start.test": [[PUBLIC]], "example.test": [[PUBLIC]]},
        {"start.test/": Reply(302, location)},
    )
    chain = go("http://start.test/", net)
    assert chain.outcome is Outcome.BLOCKED
    assert len(net.targets) == 1


def test_relative_and_scheme_relative_redirects_are_resolved_first() -> None:
    net = Net(
        {"a.test": [[PUBLIC]], "evil.test": [[PUBLIC_2]]},
        {"a.test/": Reply(302, "/two"), "a.test/two": Reply(302, "//evil.test/three")},
    )
    chain = go("http://a.test/", net)
    assert chain.outcome is Outcome.COMPLETE and chain.final_url == "http://evil.test/three"
    assert [(h.host, h.status) for h in chain.hops] == [
        ("a.test", 302),
        ("a.test", 302),
        ("evil.test", 200),
    ]


def test_redirect_loop_stops() -> None:
    net = Net(
        {"a.test": [[PUBLIC]]},
        {"a.test/1": Reply(302, "/2"), "a.test/2": Reply(302, "/1")},
    )
    assert go("http://a.test/1", net).outcome is Outcome.LOOP
    assert len(net.targets) == 2


def test_hop_cap() -> None:
    replies = {f"a.test/{i}": Reply(302, f"/{i + 1}") for i in range(50)}
    net = Net({"a.test": [[PUBLIC]]}, replies)
    chain = go("http://a.test/0", net, Limits(max_hops=3))
    assert chain.outcome is Outcome.TOO_MANY_HOPS
    assert len(net.targets) == 3


def test_oversize_redirect_target_is_invalid() -> None:
    net = Net({"a.test": [[PUBLIC]]}, {"a.test/": Reply(302, "/" + "a" * 9000)})
    assert go("http://a.test/", net).outcome is Outcome.INVALID


def test_redirect_with_no_location_ends_the_chain() -> None:
    net = Net({"a.test": [[PUBLIC]]}, {"a.test/": Reply(302, None)})
    assert go("http://a.test/", net).outcome is Outcome.COMPLETE


# ---- time and failure ------------------------------------------------------------------------


def test_slow_server_hits_the_total_deadline() -> None:
    async def slow(_: Target) -> Reply:
        await asyncio.sleep(30)
        return Reply(200, None)

    net = Net({"a.test": [[PUBLIC]]})
    chain = asyncio.run(
        follow(
            "http://a.test/",
            enabled=True,
            resolve=net.resolve,
            connect=slow,
            limits=Limits(5, 0.05),
        )
    )
    assert chain.outcome is Outcome.TIMEOUT


def test_slow_dns_hits_the_total_deadline() -> None:
    async def slow(_: str) -> list[str]:
        await asyncio.sleep(30)
        return [PUBLIC]

    net = Net({})
    chain = asyncio.run(
        follow(
            "http://a.test/",
            enabled=True,
            resolve=slow,
            connect=net.connect,
            limits=Limits(5, 0.05),
        )
    )
    assert chain.outcome is Outcome.TIMEOUT and net.targets == []


def test_the_deadline_spans_the_whole_chain_not_each_hop() -> None:
    async def creeping(t: Target) -> Reply:
        await asyncio.sleep(0.03)
        return Reply(302, f"/{len(t.path_query)}x")

    net = Net({"a.test": [[PUBLIC]]})
    chain = asyncio.run(
        follow(
            "http://a.test/",
            enabled=True,
            resolve=net.resolve,
            connect=creeping,
            limits=Limits(50, 0.1),
        )
    )
    assert chain.outcome is Outcome.TIMEOUT and 0 < len(chain.hops) < 10


def test_connection_errors_fail_closed() -> None:
    async def refused(_: Target) -> Reply:
        raise httpx.ConnectError("refused")

    net = Net({"a.test": [[PUBLIC]]})
    chain = asyncio.run(
        follow("http://a.test/", enabled=True, resolve=net.resolve, connect=refused)
    )
    assert chain.outcome is Outcome.FAILED


# ---- off by default ----------------------------------------------------------------------------


def test_off_by_default_and_silent_when_off() -> None:
    assert Settings(_env_file=None).resolve_redirects is False
    net = Net({"a.test": [[PUBLIC]]})
    chain = asyncio.run(
        follow("http://a.test/", enabled=False, resolve=net.resolve, connect=net.connect)
    )
    assert chain.outcome is Outcome.DISABLED
    assert net.lookups == [] and net.targets == []


def test_failures_never_echo_the_url() -> None:
    net = Net({})
    chain = go("http://SECRETMARK.local/SECRETMARK", net)
    assert "SECRETMARK" not in chain.detail and chain.final_url is None


# ---- the real connector, over a fake transport -------------------------------------------------


class Endless(httpx.AsyncByteStream):
    """A body that would never finish, and records whether anyone read it."""

    read = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        Endless.read = True
        while True:
            yield b"x" * 65536


def call(handler: Any, target: Target) -> Reply:
    connector = HttpxConnector(httpx.MockTransport(handler))
    return asyncio.run(connector(target))


def test_connector_pins_the_ip_and_presents_the_name() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(
            ip=request.url.host,
            port=request.url.port,
            headers=dict(request.headers),
            sni=request.extensions.get("sni_hostname"),
            path=request.url.raw_path,
        )
        return httpx.Response(302, headers={"Location": "/next", "Set-Cookie": "a=b"})

    reply = call(handler, Target("https", PUBLIC, 443, "example.test", "/p?q=1"))
    assert reply == Reply(302, "/next")
    assert seen["ip"] == PUBLIC and seen["port"] is None  # the IP, with the default port elided
    assert seen["sni"] == "example.test" and seen["headers"]["host"] == "example.test"
    assert seen["path"] == b"/p?q=1"


def test_connector_sends_nothing_identifying() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(request.headers))
        return httpx.Response(200)

    call(handler, Target("http", PUBLIC, 80, "example.test", "/"))
    assert seen["user-agent"] == USER_AGENT
    assert not {"cookie", "authorization", "referer", "x-forwarded-for"} & set(seen)


def test_cookies_do_not_survive_a_hop() -> None:
    sent: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.headers.get("cookie"))
        return httpx.Response(302, headers={"Set-Cookie": "session=abc", "Location": "/2"})

    transport = httpx.MockTransport(handler)
    connector = HttpxConnector(transport)
    for _ in range(2):
        asyncio.run(connector(Target("http", PUBLIC, 80, "example.test", "/")))
    assert sent == [None, None]


def test_the_response_body_is_never_read() -> None:
    Endless.read = False

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=Endless())

    assert call(handler, Target("http", PUBLIC, 80, "example.test", "/")).status == 200
    assert Endless.read is False


def test_ipv6_targets_are_bracketed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    call(handler, Target("http", "2606:4700:4700::1111", 80, "example.test", "/"))
    assert seen == ["http://[2606:4700:4700::1111]/"]


def test_a_non_default_port_is_kept_in_the_url_and_the_host_header() -> None:
    # The policy allows 80 and 443 for either scheme, so http on 443 is reachable.
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers["host"]))
        return httpx.Response(200)

    call(handler, Target("http", PUBLIC, 443, "example.test", "/"))
    assert seen == [(f"http://{PUBLIC}:443/", "example.test:443")]


def test_environment_proxies_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALL_PROXY", "http://proxy.test:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")

    async def check() -> bool:
        async with safe_fetch._client(None) as client:
            return client.trust_env

    assert asyncio.run(check()) is False


def test_chain_is_json_safe() -> None:
    net = Net({"a.test": [[PUBLIC]]})
    assert json.dumps(go("http://a.test/", net))
