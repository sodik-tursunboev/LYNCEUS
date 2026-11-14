"""SSRF-safe redirect following (CLAUDE.md rule 6, ADR-011). The only module that may open a socket.

Nothing calls this yet, and `enabled` has no default: resolving a link reveals the user's IP and
can burn a single-use link, so it needs an explicit operator opt-in and ADR-011 signed off. It is
never a per-request API option.

Every hop: parse as a browser would, check scheme, port and host, resolve once, require every
answer to be public, then connect to that validated IP and never to the name again, so a second DNS
answer cannot change the target. One deadline covers the whole chain. The body is never read, so
response size stays bounded by the HTTP client's header limit.
"""

import asyncio
import socket
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import NamedTuple

import ada_url
import httpx

from core.urls.addresses import is_public
from core.urls.parse import HostKind, ParsedUrl, UrlFlag, parse_url

# Honest and identical for every user: it names the tool, never the person or the machine. A
# made-up browser string ("Mozilla/5.0 (compatible)") hung against a CDN edge in a live test, and
# a real browser string would be a lie. Sites may still show scanners something different.
USER_AGENT = "LYNCEUS-LinkCheck/1.0"
ALLOWED_PORTS = frozenset({80, 443})
REDIRECTS = frozenset({301, 302, 303, 307, 308})
_INTERNAL_NAMES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp")


class Outcome(StrEnum):
    DISABLED = "DISABLED"
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"  # the guard refused; nothing was sent to that target
    INVALID = "INVALID"
    TOO_MANY_HOPS = "TOO_MANY_HOPS"
    LOOP = "LOOP"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"  # DNS, connection or TLS failure


class Limits(NamedTuple):
    max_hops: int = 5
    total_seconds: float = 8.0


class Target(NamedTuple):
    """What a connector is allowed to know: one validated IP, and the name to present to it."""

    scheme: str
    ip: str
    port: int
    host: str  # for the Host header and TLS name; never resolved again
    path_query: str


class Reply(NamedTuple):
    status: int
    location: str | None


class Hop(NamedTuple):
    host: str
    ip: str
    status: int


class Chain(NamedTuple):
    outcome: Outcome
    detail: str  # fixed text; never contains the URL
    hops: tuple[Hop, ...] = ()
    final_url: str | None = None  # sensitive, like any URL


Resolve = Callable[[str], Awaitable[list[str]]]
Connect = Callable[[Target], Awaitable[Reply]]


def _refusal(u: ParsedUrl) -> str | None:
    if u.scheme not in ("http", "https"):
        return "scheme not allowed"
    if u.has(UrlFlag.USERINFO):
        return "credentials in the URL"
    if (u.port or (443 if u.scheme == "https" else 80)) not in ALLOWED_PORTS:
        return "port not allowed"
    host = u.host or ""
    if u.host_kind is HostKind.DOMAIN and ("." not in host or host.endswith(_INTERNAL_NAMES)):
        return "internal host name"
    return None


async def system_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    answers = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(a[4][0]) for a in answers]


def _client(transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncClient:
    # trust_env=False: a proxy from the environment would take the connection out of our hands.
    # A new client per hop: nothing, cookies included, carries over between hosts.
    return httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False)


class HttpxConnector:
    """Connect to the validated IP; present the name only as Host header and TLS name."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.transport = transport

    async def __call__(self, t: Target) -> Reply:
        address = f"[{t.ip}]" if ":" in t.ip else t.ip
        default = 443 if t.scheme == "https" else 80
        host = t.host if t.port == default else f"{t.host}:{t.port}"
        tls = {"sni_hostname": t.host} if t.scheme == "https" and t.host[0] != "[" else {}
        async with _client(self.transport) as client:
            request = client.build_request(
                "GET",
                f"{t.scheme}://{address}:{t.port}{t.path_query}",
                headers={"Host": host, "User-Agent": USER_AGENT},
                extensions=tls,
            )
            response = await client.send(request, stream=True)
            try:  # headers only: closing here is what caps the response size
                return Reply(response.status_code, response.headers.get("location"))
            finally:
                await response.aclose()


async def _walk(
    url: str, resolve: Resolve, connect: Connect, limits: Limits, hops: list[Hop]
) -> Chain:
    seen: set[str] = set()
    current = url
    while True:
        u = parse_url(current)
        if not isinstance(u, ParsedUrl):
            return Chain(Outcome.INVALID, "not a valid URL", tuple(hops))
        refused = _refusal(u)  # first: javascript:, file: and data: have no host to look at
        if refused:
            return Chain(Outcome.BLOCKED, refused, tuple(hops))
        if u.host is None:
            return Chain(Outcome.INVALID, "not a valid URL", tuple(hops))
        if u.url_sha256 in seen:
            return Chain(Outcome.LOOP, "redirect loop", tuple(hops))
        if len(hops) >= limits.max_hops:
            return Chain(Outcome.TOO_MANY_HOPS, "hop limit reached", tuple(hops))
        seen.add(u.url_sha256)

        try:
            addresses = [u.ip_address] if u.ip_address else await resolve(u.host)
        except OSError:
            return Chain(Outcome.FAILED, "host name did not resolve", tuple(hops))
        if not addresses:
            return Chain(Outcome.FAILED, "host name did not resolve", tuple(hops))
        if not all(is_public(a) for a in addresses):  # one private answer taints the whole name
            return Chain(Outcome.BLOCKED, "address is not public", tuple(hops))

        ip = addresses[0]
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path + (f"?{u.query}" if u.query else "")
        try:
            reply = await connect(Target(u.scheme, ip, port, u.host, path))
        except (httpx.HTTPError, httpx.InvalidURL, OSError):
            return Chain(Outcome.FAILED, "connection failed", tuple(hops))
        hops.append(Hop(u.host, ip, reply.status))
        if reply.status not in REDIRECTS or not reply.location:
            return Chain(Outcome.COMPLETE, "reached a final response", tuple(hops), u.normalized)
        try:
            current = str(ada_url.join_url(u.normalized, reply.location))
        except ValueError:
            return Chain(Outcome.INVALID, "bad redirect target", tuple(hops))


async def follow(
    url: str,
    *,
    enabled: bool,
    resolve: Resolve = system_resolve,
    connect: Connect | None = None,
    limits: Limits = Limits(),  # noqa: B008  (immutable)
) -> Chain:
    if not enabled:
        return Chain(Outcome.DISABLED, "redirect resolution is off")
    hops: list[Hop] = []
    try:
        async with asyncio.timeout(limits.total_seconds):  # covers DNS, connect and slow headers
            return await _walk(url, resolve, connect or HttpxConnector(), limits, hops)
    except TimeoutError:
        return Chain(Outcome.TIMEOUT, "time limit reached", tuple(hops))
