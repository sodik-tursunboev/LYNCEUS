"""The detonator's only way out (D1): an HTTP forward proxy that reaches public web servers and
nothing else.

It runs in its own container, bridged between the browsers' internal network (which has no route
out) and an outer network. Every name is resolved here and every address checked; the connection
goes to the checked address, so a name that changes its answer (DNS rebinding) cannot slip through.
IPv4 only: an IPv6 address can embed a private IPv4 one in several ways, and nothing here needs it.
It logs nothing about where pages go. Standard library only.
"""

import asyncio
import ipaddress
import re
import socket
import sys
from urllib.parse import urlsplit

LISTEN_PORT = 3128
MAX_HEADER = 64 * 1024
MAX_TUNNEL_BYTES = 64 * 1024 * 1024  # each direction of one connection
MAX_CONNECTIONS = 64
IDLE_SECONDS = 30
CONNECT_SECONDS = 10
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_HOP = {"proxy-connection", "proxy-authorization", "connection", "keep-alive", "te", "upgrade"}


class Refused(Exception):
    """The request may not leave: answered with 403 and the reason, never retried."""


def public(address: str) -> bool:
    """A public unicast IPv4 address: not private, loopback, link-local (cloud metadata), shared
    (CGNAT), reserved, documentation, multicast or broadcast."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv4Address) and ip.is_global and not ip.is_multicast


def check_name(host: str) -> str:
    """A host the proxy will look up: a dotted DNS name or an IPv4 literal. Single-label names
    (container names, `localhost`) and IPv6 literals are refused before any lookup."""
    host = host.rstrip(".").lower()
    if not _HOST.fullmatch(host):
        raise Refused("bad_host")
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
        raise Refused("local_name")
    return host


async def resolve(host: str, port: int) -> str:
    """The one address to connect to. Every answer must be public: a name that also points
    somewhere private is refused outright, not filtered."""
    if re.fullmatch(r"[0-9.]+", host):
        if not public(host):
            raise Refused("private_address")
        return host
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM),
            CONNECT_SECONDS,
        )
    except (OSError, TimeoutError) as e:
        raise Refused("dns") from e
    addresses = sorted({str(i[4][0]) for i in infos})
    if not addresses:
        raise Refused("dns")
    if not all(public(a) for a in addresses):
        raise Refused("private_address")
    return addresses[0]


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    total = 0
    try:
        while True:
            chunk = await asyncio.wait_for(src.read(65536), IDLE_SECONDS)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TUNNEL_BYTES:
                break
            dst.write(chunk)
            await dst.drain()
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        dst.close()


async def _splice(
    cr: asyncio.StreamReader,
    cw: asyncio.StreamWriter,
    ur: asyncio.StreamReader,
    uw: asyncio.StreamWriter,
) -> None:
    await asyncio.gather(_pipe(cr, uw), _pipe(ur, cw))


async def _open(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    address = await resolve(check_name(host), port)
    try:
        return await asyncio.wait_for(asyncio.open_connection(address, port), CONNECT_SECONDS)
    except (OSError, TimeoutError) as e:
        raise Refused("connect") from e


def _split_target(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit():
        raise Refused("bad_target")
    return host, int(port)


def rewrite(method: str, target: str, lines: list[str]) -> tuple[str, int, bytes]:
    """A plain-HTTP proxy request in absolute form, as the request to send to the origin: origin
    form, hop-by-hop headers dropped, and `Connection: close` so one connection is one request."""
    u = urlsplit(target)
    if u.scheme != "http" or not u.hostname:
        raise Refused("bad_target")
    port = u.port or 80
    if port != 80:
        raise Refused("port")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    kept = [ln for ln in lines if ln and ln.split(":", 1)[0].strip().lower() not in _HOP]
    head = "\r\n".join([f"{method} {path} HTTP/1.1", *kept, "Connection: close", "", ""])
    return u.hostname, port, head.encode("latin-1")


async def handle(
    cr: asyncio.StreamReader, cw: asyncio.StreamWriter, slots: asyncio.Semaphore
) -> None:
    async with slots:
        try:
            raw = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), IDLE_SECONDS)
            line, *lines = raw.decode("latin-1").split("\r\n")
            method, target, _ = line.split(" ", 2)
            if method == "CONNECT":
                host, port = _split_target(target)
                if port != 443:
                    raise Refused("port")
                ur, uw = await _open(host, port)
                cw.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await cw.drain()
            else:
                host, port, head = rewrite(method, target, lines)
                ur, uw = await _open(host, port)
                uw.write(head)
                await uw.drain()
            await _splice(cr, cw, ur, uw)
        except Refused as e:
            body = f"refused: {e}\n".encode()
            cw.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(body), body))  # fmt: skip
        except (OSError, TimeoutError, ValueError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):  # fmt: skip
            pass
        finally:
            cw.close()


async def main() -> None:
    slots = asyncio.Semaphore(MAX_CONNECTIONS)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, slots), "0.0.0.0", LISTEN_PORT, limit=MAX_HEADER
    )
    print("egress proxy ready", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
