"""No test may reach the network. Loopback stays open: asyncio on Windows needs a loopback socket
pair, and the PostgreSQL tests talk to a local container (through libpq, not this module)."""

import os
import socket
from collections.abc import Iterator
from typing import Any

import pytest

_LOCAL = {None, "", "localhost", "127.0.0.1", "::1"}


@pytest.fixture(autouse=True, scope="session")
def no_network() -> Iterator[None]:
    if os.environ.get("MIRAGE_LIVE_FETCH") == "1":  # the manual real-socket test, run on purpose
        yield
        return
    real_connect, real_lookup = socket.socket.connect, socket.getaddrinfo

    def connect(self: socket.socket, address: Any) -> None:
        if isinstance(address, tuple) and address[0] not in _LOCAL:
            raise RuntimeError(f"test tried to reach the network: {address[0]}")
        real_connect(self, address)

    def lookup(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host not in _LOCAL:
            raise RuntimeError(f"test tried a DNS lookup: {host}")
        return real_lookup(host, *args, **kwargs)

    patch = pytest.MonkeyPatch()
    patch.setattr(socket.socket, "connect", connect)
    patch.setattr(socket, "getaddrinfo", lookup)
    yield
    patch.undo()
