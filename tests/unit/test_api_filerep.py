"""DA2: the API asks VirusTotal about a downloaded file's hash only when switched on, only for
program-like names, never for a file the local lists already know, and a failing lookup costs the
verdict nothing. The sandbox is the in-process scanner; VirusTotal is a mock transport."""

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import filehelp as fh
import httpx
import pytest
from fastapi.testclient import TestClient
from mailhelp import in_process_file

from core import hashlists
from core.api.app import create_app
from core.config import Settings
from core.files import engine as file_engine
from core.intel import registry
from core.intel.http import make_client

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
KEY = "VT-API-FILE-KEY-999"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
OCTET = {"Content-Type": "application/octet-stream"}
EXE = b"MZ\x90\x00" + b"\x00" * 60
SHA = hashlib.sha256(EXE).hexdigest()


def report(malicious: int) -> dict[str, Any]:
    stats = {"malicious": malicious, "suspicious": 0, "harmless": 0, "undetected": 60}
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_engine, "run_inspect_bytes", in_process_file)


def app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    answer: Callable[[httpx.Request], httpx.Response],
    **over: Any,
) -> tuple[TestClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return answer(request)

    monkeypatch.setattr(
        registry, "make_client", lambda *a, **k: make_client(httpx.MockTransport(respond))
    )
    over.setdefault("data_dir", tmp_path / "data")
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(create_app(settings), base_url="http://127.0.0.1"), seen


def send(c: TestClient, name: str, data: bytes) -> Any:
    h = AUTH | OCTET | {"X-Lynceus-Name": quote(name, safe="")}
    return c.post("/v1/files/analyze", content=data, headers=h)


def on(**more: Any) -> dict[str, Any]:
    return {"file_reputation": True, "virustotal_api_key": KEY, **more}


def test_nothing_is_asked_unless_switched_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, seen = app(monkeypatch, tmp_path, lambda r: httpx.Response(200, json=report(30)))
    body = send(c, "setup.exe", EXE).json()
    assert seen == [] and body["verdict"]["state"] == "UNKNOWN"


def test_only_program_like_files_are_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    c, seen = app(monkeypatch, tmp_path, lambda r: httpx.Response(404), **on())
    for name, data in (
        ("notes.txt", b"words"),
        ("report.pdf", fh.PDF_PLAIN),
        ("photo.png", fh.blank_png()),
    ):
        assert send(c, name, data).status_code == 200
    assert seen == []
    assert send(c, "SECRET-folder-setup.exe", EXE).status_code == 200
    (request,) = seen
    assert str(request.url) == f"https://www.virustotal.com/api/v3/files/{SHA}"
    assert request.headers["x-apikey"] == KEY and not request.content and request.url.query == b""
    assert "SECRET" not in str(request.url) and "setup" not in str(request.headers)


def test_many_engines_make_the_download_malicious_and_it_is_audited(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, seen = app(monkeypatch, tmp_path, lambda r: httpx.Response(200, json=report(31)), **on())
    r = send(c, "setup.exe", EXE)
    body = r.json()
    assert body["verdict"]["state"] == "MALICIOUS"
    assert "file.vt_known_bad" in {s["rule_id"] for s in body["verdict"]["signals"]}
    assert len(seen) == 1 and KEY not in r.text
    again = send(c, "setup.exe", EXE)  # the same file: answered from memory, not asked again
    assert again.json()["verdict"]["state"] == "MALICIOUS" and len(seen) == 1


def test_a_locally_known_bad_file_is_not_asked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    listing = tmp_path / "bad.txt"
    listing.write_text(SHA + "\n", encoding="utf-8")
    hashlists.import_list(listing, "test-list", tmp_path / "data" / "hashes")
    c, seen = app(monkeypatch, tmp_path, lambda r: httpx.Response(200, json=report(0)), **on())
    body = send(c, "setup.exe", EXE).json()
    assert body["verdict"]["state"] == "MALICIOUS" and seen == []


@pytest.mark.parametrize("failure", ["500", "401", "429", "garbage", "raises"])
def test_a_failing_lookup_leaves_the_verdict_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    def answer(r: httpx.Request) -> httpx.Response:
        if failure == "raises":
            raise httpx.ConnectError("no network")
        if failure == "garbage":
            return httpx.Response(200, content=b"not json")
        return httpx.Response(int(failure))

    plain, _ = app(monkeypatch, tmp_path, answer)
    baseline = send(plain, "setup.exe", EXE).json()["verdict"]
    c, seen = app(monkeypatch, tmp_path, answer, **on())
    got = send(c, "setup.exe", EXE)
    verdict = got.json()["verdict"]
    assert got.status_code == 200 and len(seen) == 1
    assert (verdict["state"], verdict["risk_score"]) == (baseline["state"], baseline["risk_score"])
    assert verdict["state"] != "BENIGN"


def test_switching_it_on_without_the_key_stops_start_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in ("LYNCEUS_VIRUSTOTAL_API_KEY", "MIRAGE_VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("core.secrets.STORE", tmp_path / "none.json")
    with pytest.raises(ValueError, match="LYNCEUS_VIRUSTOTAL_API_KEY is not set"):
        app(monkeypatch, tmp_path, lambda r: httpx.Response(404), file_reputation=True)
