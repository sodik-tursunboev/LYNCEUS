"""POST /v1/files/analyze, POST /v1/files/check and POST /v1/overrides (M4). The sandbox is the
in-process guest scanner; the database is a throwaway SQLite file."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import filehelp as fh
import pytest
from fastapi.testclient import TestClient
from mailhelp import in_process_file
from sqlalchemy import create_engine, select

from core.api.app import create_app
from core.config import Settings
from core.db import models as db
from core.files import engine as file_engine

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
EXE = b"MZ\x90\x00" + b"\x00" * 60
OCTET = {"Content-Type": "application/octet-stream"}


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_engine, "run_inspect_bytes", in_process_file)


def client(tmp_path: Path, **over: Any) -> TestClient:
    over.setdefault("data_dir", tmp_path / "data")
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def send(c: TestClient, name: str, data: bytes, **headers: str) -> Any:
    h = AUTH | OCTET | {"X-Mirage-Name": quote(name, safe="")} | headers
    return c.post("/v1/files/analyze", content=data, headers=h)


def sqlite_url(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    db.Base.metadata.create_all(create_engine(url))
    return url


# ---- files with bytes ----------------------------------------------------------------------------


def test_a_disguised_executable_is_flagged_and_the_name_is_not_echoed(tmp_path: Path) -> None:
    r = send(client(tmp_path), "SECRETNAME-invoice.pdf.exe", EXE)
    body = r.json()
    assert r.status_code == 200 and body["inspected"] is True and body["persisted"] is False
    assert body["verdict"]["state"] in ("SUSPICIOUS", "MALICIOUS")
    assert body["verdict"]["applied_response"] == "NONE"
    assert "email.double_extension" in {s["rule_id"] for s in body["verdict"]["signals"]}
    assert "SECRETNAME" not in r.text


def test_a_plain_file_is_unknown_and_pdf_contents_are_opened(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert send(c, "notes.txt", b"words").json()["verdict"]["state"] == "UNKNOWN"
    body = send(c, "a.pdf", fh.PDF_JS).json()
    assert "email.pdf_javascript" in {s["rule_id"] for s in body["verdict"]["signals"]}
    assert body["files"][0]["kind"] == "pdf"


def test_the_origin_host_and_a_correct_hash_are_accepted(tmp_path: Path) -> None:
    import hashlib

    sha = hashlib.sha256(EXE).hexdigest()
    r = send(
        client(tmp_path),
        "a.exe",
        EXE,
        **{"X-Mirage-Sha256": sha, "X-Mirage-Origin-Host": "origin.test"},
    )
    assert r.status_code == 200 and r.json()["reason"] is None


def test_a_hash_that_does_not_match_the_bytes_is_reported_not_trusted(tmp_path: Path) -> None:
    r = send(client(tmp_path), "a.exe", EXE, **{"X-Mirage-Sha256": "00" * 32})
    assert (
        r.json()["reason"] == "changed_while_reading" and r.json()["verdict"]["state"] == "UNKNOWN"
    )


@pytest.mark.parametrize("name", ["", "a\x00b", "x" * 5000])
def test_a_missing_or_absurd_name_is_a_422(tmp_path: Path, name: str) -> None:
    h = AUTH | OCTET | ({"X-Mirage-Name": quote(name, safe="")} if name else {})
    assert client(tmp_path).post("/v1/files/analyze", content=EXE, headers=h).status_code == 422


def test_only_octet_stream_is_accepted(tmp_path: Path) -> None:
    r = client(tmp_path).post(
        "/v1/files/analyze",
        content=EXE,
        headers=AUTH | {"Content-Type": "application/json", "X-Mirage-Name": "a"},
    )
    assert r.status_code == 415


def test_body_cap_token_and_parser_slots(tmp_path: Path) -> None:
    assert send(client(tmp_path, max_file_bytes=100), "a.bin", b"x" * 500).status_code == 413
    assert client(tmp_path).post("/v1/files/analyze", content=EXE, headers=OCTET).status_code == 401
    assert send(client(tmp_path, max_concurrent_parsers=0), "a.bin", b"x").status_code == 503


def test_the_file_cap_does_not_change_the_url_cap(tmp_path: Path) -> None:
    c = client(tmp_path, max_body_bytes=100, max_file_bytes=100_000)
    assert send(c, "a.exe", EXE * 5).status_code == 200
    assert c.post("/v1/urls/analyze", json={"url": "a" * 200}, headers=AUTH).status_code == 413


def test_a_launcher_failure_is_an_error_verdict_not_a_500(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_d: bytes) -> Any:
        raise OSError("CreateProcess failed")

    monkeypatch.setattr(file_engine, "run_inspect_bytes", broken)
    r = send(client(tmp_path), "a.bin", b"abc")
    assert r.status_code == 200 and r.json()["verdict"]["state"] == "ERROR"


# ---- metadata only -------------------------------------------------------------------------------


def test_a_file_the_agent_did_not_send_is_judged_by_name_and_type(tmp_path: Path) -> None:
    c = client(tmp_path)
    body = {
        "name": "setup.scr",
        "size": 123456,
        "sha256": "ab" * 32,
        "magic": "exe",
        "origin_host": "x.test",
    }
    r = c.post("/v1/files/check", json=body, headers=AUTH)
    assert r.status_code == 200 and r.json()["inspected"] is False
    assert "email.dangerous_attachment" in {s["rule_id"] for s in r.json()["verdict"]["signals"]}


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "a", "size": 1, "sha256": "short"},
        {"name": "a", "size": -1, "sha256": "ab" * 32},
        {"name": "a", "size": 1, "sha256": "ab" * 32, "extra": 1},
        {"size": 1, "sha256": "ab" * 32},
        {"name": "x" * 2000, "size": 1, "sha256": "ab" * 32},
    ],
)
def test_malformed_metadata_is_a_422(tmp_path: Path, bad: dict[str, Any]) -> None:
    assert client(tmp_path).post("/v1/files/check", json=bad, headers=AUTH).status_code == 422


# ---- storage -------------------------------------------------------------------------------------


def test_a_file_is_stored_by_hash_and_origin_host_only(tmp_path: Path) -> None:
    url = sqlite_url(tmp_path)
    c = client(tmp_path, database_url=url)
    pdf = fh.pdf_with_uris("https://paypal-login.test/PATHMARK?q=QUERYMARK")
    r = send(c, "FILEMARK-statement.pdf", pdf, **{"X-Mirage-Origin-Host": "origin-site.test"})
    assert r.status_code == 200 and r.json()["persisted"] is True
    with create_engine(url).connect() as conn:
        art = conn.execute(select(db.Artifact)).one()
        dump = "\n".join(
            repr(row) for t in db.Base.metadata.sorted_tables for row in conn.execute(select(t))
        )
        sources = {e.source for e in conn.execute(select(db.Event))}
    assert (art.kind, art.host) == ("FILE", "origin-site.test") and len(art.sha256) == 64
    assert sources == {"AGENT"}
    for private in ("FILEMARK", "PATHMARK", "QUERYMARK", "statement.pdf"):
        assert private not in dump, private


# ---- overrides -----------------------------------------------------------------------------------

OVERRIDE = {
    "url": "https://paypal-login.test/PATHMARK/login.php?token=QUERYMARK#frag",
    "minutes": 15,
}


def test_an_override_is_recorded_with_host_and_hash_never_the_url(tmp_path: Path) -> None:
    url = sqlite_url(tmp_path)
    c = client(tmp_path, database_url=url)
    r = c.post("/v1/overrides", json=OVERRIDE | {"state": "MALICIOUS"}, headers=AUTH)
    body = r.json()
    assert r.status_code == 200 and body["recorded"] is True and body["stored_in"] == "database"
    delta = datetime.fromisoformat(body["expires_at"]) - datetime.now(UTC)
    assert 14 * 60 < delta.total_seconds() <= 15 * 60
    with create_engine(url).connect() as conn:
        row = conn.execute(select(db.AuditLog)).one()
    assert (row.actor, row.action, row.target_type) == ("user", "override.grant", "url")
    assert row.detail["host"] == "paypal-login.test" and len(row.detail["url_sha256"]) == 64
    assert row.detail["overridden_state"] == "MALICIOUS" and row.detail["minutes"] == 15
    assert "PATHMARK" not in json.dumps(row.detail) and "QUERYMARK" not in json.dumps(row.detail)


def test_without_a_database_the_override_goes_to_an_audit_file(tmp_path: Path) -> None:
    c = client(tmp_path)
    r = c.post("/v1/overrides", json=OVERRIDE, headers=AUTH)
    assert r.json()["stored_in"] == "file"
    lines = (tmp_path / "data" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    assert record["action"] == "override.grant" and record["detail"]["host"] == "paypal-login.test"
    assert "PATHMARK" not in lines[0] and "QUERYMARK" not in lines[0]


def test_an_override_that_cannot_be_recorded_is_refused(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_text("a file where the folder should be", encoding="utf-8")
    r = client(tmp_path).post("/v1/overrides", json=OVERRIDE, headers=AUTH)
    assert r.status_code == 503


@pytest.mark.parametrize(
    "bad",
    [
        {"url": "http://ex ample.test/"},
        {"url": ""},
        {**OVERRIDE, "minutes": 0},
        {**OVERRIDE, "minutes": 61},
        {**OVERRIDE, "extra": True},
        {"minutes": 15},
    ],
)
def test_a_bad_override_request_is_422(tmp_path: Path, bad: dict[str, Any]) -> None:
    assert client(tmp_path).post("/v1/overrides", json=bad, headers=AUTH).status_code == 422


def test_overrides_and_file_routes_need_the_token(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.post("/v1/overrides", json=OVERRIDE).status_code == 401
    assert (
        c.post("/v1/files/check", json={"name": "a", "size": 1, "sha256": "ab" * 32}).status_code
        == 401
    )
