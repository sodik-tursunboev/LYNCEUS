"""python -m core.intel: sync, status, lookup. Downloads go through a mock transport."""

import bz2
import json
import os
from pathlib import Path

import httpx
import pytest

from core import secrets
from core.config import Settings
from core.intel import __main__ as cli
from core.intel import registry
from core.intel.http import make_client


def feed_bytes(*urls: str) -> bytes:
    return bz2.compress(json.dumps([{"url": u} for u in urls]).encode())


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("LYNCEUS_INTEL_PROVIDERS", "LYNCEUS_PHISHTANK_KEY", "LYNCEUS_URLHAUS_AUTH_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LYNCEUS_DATA_DIR", str(tmp_path / "data"))
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
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "openphish")
    seen = serve(monkeypatch, lambda r: httpx.Response(200))
    assert cli.main(["sync", "--feed", "phishtank"]) == 2
    assert "not enabled" in capsys.readouterr().err and seen == []


def test_sync_status_and_lookup_work_together(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "phishtank")
    monkeypatch.setenv("LYNCEUS_PHISHTANK_KEY", "KEY-SECRET-123")
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
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "openphish")
    serve(monkeypatch, lambda r: httpx.Response(503))
    assert cli.main(["sync"]) == 1
    assert "http 503" in capsys.readouterr().out


VT_KEY = "VT-KEY-FROM-THE-STORE-123"  # pragma: allowlist secret
VT_ONE_ENGINE = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 70}}}}


def ask_serve(monkeypatch: pytest.MonkeyPatch, handler: object) -> list[httpx.Request]:
    """The providers that ask an outside service are built by the registry, not by this module."""
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)  # type: ignore[operator, no-any-return]

    monkeypatch.setattr(
        registry, "make_client", lambda *a, **k: make_client(httpx.MockTransport(respond))
    )
    return seen


@pytest.fixture
def no_vt_key(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LYNCEUS_VIRUSTOTAL_API_KEY", "MIRAGE_VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(secrets, "STORE", env / "none.json")


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows only")
@pytest.mark.usefixtures("no_vt_key")
def test_ask_sends_one_domain_and_uses_the_stored_key(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets.put("virustotal_api_key", VT_KEY, env / "s.json")
    monkeypatch.setattr(secrets, "STORE", env / "s.json")  # the key is in the store, nowhere else
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "virustotal")
    seen = ask_serve(monkeypatch, lambda r: httpx.Response(200, json=VT_ONE_ENGINE))
    url = "https://login.newshop.com/a/b?token=SECRET-TOKEN#frag"
    assert cli.main(["lookup", url, "--ask"]) == 0
    out = capsys.readouterr().out
    (request,) = seen
    assert str(request.url) == "https://www.virustotal.com/api/v3/domains/newshop.com"
    assert request.headers["x-apikey"] == VT_KEY and not request.content
    assert "virustotal" in out and "OK" in out and "SUSPICIOUS" in out
    assert VT_KEY not in out and "SECRET-TOKEN" not in out


@pytest.mark.usefixtures("no_vt_key")
def test_lookup_without_ask_sends_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "virustotal")
    monkeypatch.setenv("LYNCEUS_VIRUSTOTAL_API_KEY", VT_KEY)
    seen = ask_serve(monkeypatch, lambda r: httpx.Response(200, json=VT_ONE_ENGINE))
    assert cli.main(["lookup", "https://newshop.com/"]) == 0
    assert seen == [] and "no list feeds are enabled" in capsys.readouterr().out


@pytest.mark.usefixtures("no_vt_key")
def test_a_rejected_key_is_an_error_never_clean(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "virustotal")
    monkeypatch.setenv("LYNCEUS_VIRUSTOTAL_API_KEY", VT_KEY)
    ask_serve(
        monkeypatch,
        lambda r: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}),
    )
    assert cli.main(["lookup", "https://newshop.com/", "--ask"]) == 0
    out = capsys.readouterr().out
    assert "virustotal" in out and "ERROR" in out and "credentials rejected" in out
    assert " OK " not in out and "BENIGN" not in out and VT_KEY not in out


@pytest.mark.usefixtures("no_vt_key")
def test_virustotal_without_a_key_stops_start_up(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "virustotal")
    seen = ask_serve(monkeypatch, lambda r: httpx.Response(200, json=VT_ONE_ENGINE))
    assert cli.main(["lookup", "https://newshop.com/", "--ask"]) == 2
    assert "LYNCEUS_VIRUSTOTAL_API_KEY is not set" in capsys.readouterr().err and seen == []
    with pytest.raises(ValueError, match="LYNCEUS_VIRUSTOTAL_API_KEY is not set"):
        registry.build_intel(
            Settings(_env_file=None, intel_providers="virustotal")
        )  # the core refuses too


def test_lookup_before_any_download_says_unavailable_not_clean(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LYNCEUS_INTEL_PROVIDERS", "phishtank")
    assert cli.main(["lookup", "http://x.test/"]) == 0
    out = capsys.readouterr().out
    assert "UNAVAILABLE" in out and "not downloaded" in out
