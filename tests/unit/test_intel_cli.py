"""python -m core.intel: sync, status, lookup. Downloads go through a mock transport."""

import bz2
import json
from pathlib import Path

import httpx
import pytest

from core.intel import __main__ as cli
from core.intel.http import make_client


def feed_bytes(*urls: str) -> bytes:
    return bz2.compress(json.dumps([{"url": u} for u in urls]).encode())


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("MIRAGE_INTEL_PROVIDERS", "MIRAGE_PHISHTANK_KEY", "MIRAGE_URLHAUS_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MIRAGE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)  # no .env here: only what the test sets counts
    return tmp_path


def serve(monkeypatch: pytest.MonkeyPatch, handler: object) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)  # type: ignore[operator, no-any-return]

    monkeypatch.setattr(
        cli, "make_client", lambda timeout=30.0: make_client(httpx.MockTransport(respond))
    )
    return seen


def test_nothing_is_enabled_by_default(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "enabled: (none)" in out and "phishtank  off" in out
    assert cli.main(["sync"]) == 0 and "no list feeds are enabled" in capsys.readouterr().out


def test_sync_refuses_a_feed_the_operator_did_not_enable(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIRAGE_INTEL_PROVIDERS", "openphish")
    seen = serve(monkeypatch, lambda r: httpx.Response(200))
    assert cli.main(["sync", "--feed", "phishtank"]) == 2
    assert "not enabled" in capsys.readouterr().err and seen == []


def test_sync_status_and_lookup_work_together(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIRAGE_INTEL_PROVIDERS", "phishtank")
    monkeypatch.setenv("MIRAGE_PHISHTANK_KEY", "KEY-SECRET-123")
    seen = serve(
        monkeypatch, lambda r: httpx.Response(200, content=feed_bytes("http://evil-site.test/a"))
    )
    assert cli.main(["sync"]) == 0
    out = capsys.readouterr().out
    assert "updated" in out and "KEY-SECRET-123" not in out
    assert "KEY-SECRET-123" in str(seen[0].url)  # the key travels in the download URL only
    assert cli.main(["status"]) == 0 and "1 entries" in capsys.readouterr().out
    assert cli.main(["lookup", "http://evil-site.test/a"]) == 0
    assert "MALICIOUS" in capsys.readouterr().out
    assert cli.main(["lookup", "http://clean-site.test/"]) == 0
    assert "UNKNOWN" in capsys.readouterr().out


def test_a_failed_sync_exits_non_zero_and_says_why(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIRAGE_INTEL_PROVIDERS", "openphish")
    serve(monkeypatch, lambda r: httpx.Response(503))
    assert cli.main(["sync"]) == 1
    assert "http 503" in capsys.readouterr().out


def test_lookup_before_any_download_says_unavailable_not_clean(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MIRAGE_INTEL_PROVIDERS", "phishtank")
    assert cli.main(["lookup", "http://x.test/"]) == 0
    out = capsys.readouterr().out
    assert "UNAVAILABLE" in out and "not downloaded" in out
