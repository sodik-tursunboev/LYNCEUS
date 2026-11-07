"""The loop that keeps the downloaded lists fresh while the core runs.

No network: the client and the download step are replaced."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from core.config import Settings
from core.intel import refresh
from core.intel.feeds import FEEDS, FeedStore, SyncOutcome


@dataclass
class Fake:
    seen: list[tuple[str, str | None]] = field(default_factory=list)  # (feed, key it was given)
    outcomes: dict[str, SyncOutcome | Exception] = field(default_factory=dict)

    def count(self, name: str) -> int:
        return sum(1 for n, _k in self.seen if n == name)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Fake:
    state = Fake()

    @asynccontextmanager
    async def client(**_kw: Any):  # type: ignore[no-untyped-def]
        yield object()

    async def download(spec, _store, _client, *, key=None, **_kw):  # type: ignore[no-untyped-def]
        state.seen.append((spec.name, key))
        out = state.outcomes.get(spec.name)
        if isinstance(out, Exception):
            raise out
        return out or SyncOutcome(spec.name, "fresh", 1, "downloaded recently")

    monkeypatch.setattr(refresh, "make_client", client)
    monkeypatch.setattr(refresh, "sync", download)
    return state


async def _run(
    store: FeedStore, names: list[str], keys: dict[str, str | None], seconds: float, **kw: float
) -> None:
    task = asyncio.create_task(refresh.keep_fresh(store, names, keys, **kw))
    await asyncio.sleep(seconds)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def test_every_enabled_feed_is_checked_again_and_again(tmp_path: Path, fake: Fake) -> None:
    asyncio.run(_run(FeedStore(tmp_path), ["openphish", "phishtank"], {}, 0.15, check_every=0.02))
    assert fake.count("openphish") >= 3 and fake.count("phishtank") >= 3


def test_a_failed_feed_waits_before_it_is_asked_again(tmp_path: Path, fake: Fake) -> None:
    fake.outcomes["openphish"] = SyncOutcome("openphish", "error", 0, "timeout")
    keys: dict[str, str | None] = {"urlhaus": "k"}
    asyncio.run(
        _run(
            FeedStore(tmp_path),
            ["openphish", "urlhaus"],
            keys,
            0.15,
            check_every=0.02,
            retry_after=60,
        )
    )
    assert fake.count("openphish") == 1  # one failure, then left alone
    assert fake.count("urlhaus") >= 3  # the others carry on


def test_an_exception_in_a_download_never_stops_the_loop(tmp_path: Path, fake: Fake) -> None:
    fake.outcomes["openphish"] = RuntimeError("boom")
    asyncio.run(_run(FeedStore(tmp_path), ["openphish"], {}, 0.15, check_every=0.02))
    assert fake.count("openphish") >= 3


def test_the_key_reaches_only_its_own_feed(tmp_path: Path, fake: Fake) -> None:
    keys: dict[str, str | None] = {"phishtank": "KEY"}
    asyncio.run(_run(FeedStore(tmp_path), ["openphish", "phishtank"], keys, 0.05, check_every=0.02))
    assert set(fake.seen) == {("openphish", None), ("phishtank", "KEY")}


def test_a_feed_used_without_a_key_is_asked_for_less_often() -> None:
    keyless = refresh.spec_for("phishtank", None)
    keyed = refresh.spec_for("phishtank", "KEY")
    assert keyless.interval == refresh.KEYLESS_INTERVAL
    assert keyed.interval == FEEDS["phishtank"].interval < keyless.interval
    assert refresh.spec_for("openphish", None) is FEEDS["openphish"]  # needs no key: unchanged


def test_keys_come_from_settings_as_plain_strings_or_none(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("PHISHTANK_KEY", "URLHAUS_AUTH_KEY"):
        monkeypatch.delenv("LYNCEUS_" + name, raising=False)
        monkeypatch.delenv("MIRAGE_" + name, raising=False)
    monkeypatch.setenv("LYNCEUS_URLHAUS_AUTH_KEY", "abc123")
    keys = refresh.feed_keys(Settings(_env_file=None))  # type: ignore[call-arg]
    assert keys == {"phishtank": None, "urlhaus": "abc123"}
