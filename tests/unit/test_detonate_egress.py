"""The detonator's egress proxy (D1) refuses everything that is not a public web server, and the
container command keeps its hardening. No network is used: every case here is refused before any
connection is attempted."""

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from core.detonate.runner import INNER, command

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "egress", ROOT / "infra" / "detonator" / "egress.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["egress"] = module
    spec.loader.exec_module(module)
    return module


egress = _load()


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1",
        "0.0.0.0", "255.255.255.255", "224.0.0.1", "192.0.2.10", "198.51.100.7", "::1",
        "2001:db8::1", "::ffff:10.0.0.1", "not-an-ip",
    ],
)  # fmt: skip
def test_only_public_ipv4_is_public(address: str) -> None:
    assert not egress.public(address)


def test_a_public_address_is_public() -> None:
    assert egress.public("93.184.215.14")


@pytest.mark.parametrize(
    "host",
    [
        "localhost", "lynceus-egress", "host.docker.internal", "gateway.docker.internal",
        "printer.local", "x.localhost", "[::1]", "exa mple.com", "a" * 300 + ".com", "",
    ],
)  # fmt: skip
def test_local_and_malformed_names_are_refused_before_any_lookup(host: str) -> None:
    with pytest.raises(egress.Refused):
        egress.check_name(host)


@pytest.mark.parametrize("host", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.0.10"])
def test_private_ip_literals_are_refused_without_a_lookup(host: str) -> None:
    with pytest.raises(egress.Refused, match="private_address"):
        asyncio.run(egress.resolve(host, 443))


def test_a_plain_http_request_is_rewritten_for_the_origin() -> None:
    lines = ["Host: example.com", "Proxy-Connection: keep-alive", "Proxy-Authorization: x",
             "Connection: keep-alive", "Accept: */*"]  # fmt: skip
    host, port, head = egress.rewrite("GET", "http://example.com/a/b?c=1", lines)
    text = head.decode()
    assert (host, port) == ("example.com", 80)
    assert text.startswith("GET /a/b?c=1 HTTP/1.1\r\n")
    assert "Proxy-" not in text and "keep-alive" not in text
    assert text.endswith("Accept: */*\r\nConnection: close\r\n\r\n")


@pytest.mark.parametrize("target", ["http://example.com:8080/", "https://example.com/", "ftp://x/"])
def test_plain_http_only_on_port_80(target: str) -> None:
    with pytest.raises(egress.Refused):
        egress.rewrite("GET", target, [])


class _Writer:
    def __init__(self) -> None:
        self.data = b""

    def write(self, b: bytes) -> None:
        self.data += b

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


def _ask(raw: bytes) -> bytes:
    async def go() -> bytes:
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()
        w = _Writer()
        await egress.handle(reader, w, asyncio.Semaphore(1))
        return w.data

    return asyncio.run(go())


@pytest.mark.parametrize(
    "request_line",
    [
        b"CONNECT 10.0.0.1:443 HTTP/1.1",
        b"CONNECT 169.254.169.254:443 HTTP/1.1",
        b"CONNECT host.docker.internal:443 HTTP/1.1",
        b"CONNECT example.com:22 HTTP/1.1",
        b"CONNECT [::1]:443 HTTP/1.1",
        b"GET http://127.0.0.1:8765/health HTTP/1.1",
        b"GET http://lynceus-egress/ HTTP/1.1",
    ],
)
def test_the_proxy_answers_403_to_everything_local(request_line: bytes) -> None:
    answer = _ask(request_line + b"\r\nHost: x\r\n\r\n")
    assert answer.startswith(b"HTTP/1.1 403 Forbidden")


def test_the_browser_container_keeps_its_hardening() -> None:
    cmd = command("lynceus-dn-test")
    joined = " ".join(cmd)
    for flag in ("--rm", "--read-only", "--user pwuser", "--cap-drop ALL", "--cap-add SYS_CHROOT",
                 "no-new-privileges", "seccomp=", "--memory 1g", "--pids-limit 512",
                 "--init"):  # fmt: skip
        assert flag in joined, flag
    assert cmd[cmd.index("--network") + 1] == INNER
    assert (
        "-v" not in cmd and "--volume" not in cmd and "-p" not in cmd and "--privileged" not in cmd
    )
    assert cmd.count("--cap-add") == 1
