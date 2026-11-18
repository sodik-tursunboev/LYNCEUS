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
    if os.environ.get("LYNCEUS_LIVE_FETCH") == "1":  # the manual real-socket test, run on purpose
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


@pytest.fixture
def no_learned_model() -> Iterator[None]:
    """For tests about the address rules, a provider's answer or a page: the learned domain model
    (AI1) changes with every retraining and adds its own category, so these must not depend on it.
    Tests of the model itself do not use this."""
    from core.learn import model

    before = model.current()
    model.use(None)
    try:
        yield
    finally:
        model.use(before)


@pytest.fixture(autouse=True)
def no_popular_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts without the popular-domain list (H1 B1), whatever a local `sync` put in
    .data: verdicts in tests must not depend on a downloaded file. Tests that need it call `use`."""
    from core.urls import popular

    monkeypatch.setattr(popular, "configure", lambda directory: None)
    popular.use(frozenset())
