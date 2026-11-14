"""H1 A1: the console never holds the API token, and a console session can only act as the person.

Attack tests: a used or expired code is refused, a console session cannot claim `policy`, cannot
report what the agent did, cannot mint codes, and a sign-out ends the session."""

import uuid
from pathlib import Path
from typing import Any

import filehelp as fh
import pytest
from fastapi.testclient import TestClient
from mailhelp import in_process_file
from sqlalchemy import create_engine, select

from core.api import sessions as sessions_mod
from core.api.app import create_app
from core.config import Settings
from core.db import models as db
from core.files import engine as file_engine

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AGENT = {"Authorization": f"Bearer {TOKEN}"}
BAD_PDF = fh.make_pdf(
    "/OpenAction 4 0 R",
    [
        "<< /S /Launch /F (cmd.exe) >>",
        "<< /S /JavaScript /JS (x) >>",
        "<< /S /URI /URI (https://paypal-login.test/login.php?email=jane%40example.test) >>",
    ],
)


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_engine, "run_inspect_bytes", in_process_file)


@pytest.fixture
def world(tmp_path: Path) -> tuple[TestClient, Any]:
    url = f"sqlite:///{tmp_path / 'lynceus.db'}"
    engine = create_engine(url)
    db.Base.metadata.create_all(engine)
    settings = Settings(_env_file=None, api_token=TOKEN, database_url=url, data_dir=tmp_path / "d")
    return TestClient(create_app(settings), base_url="http://127.0.0.1"), engine


def console(c: TestClient) -> dict[str, str]:
    code = c.post("/v1/console/code", headers=AGENT).json()["code"]
    r = c.post("/v1/console/session", json={"code": code})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def pending(c: TestClient) -> str:
    h = AGENT | {"Content-Type": "application/octet-stream", "X-Lynceus-Name": "x.pdf",
                 "X-Lynceus-File-Id": "a" * 32}  # fmt: skip
    r = c.post("/v1/files/analyze", content=BAD_PDF, headers=h)
    assert r.json()["verdict"]["state"] == "MALICIOUS", r.text
    return str(r.json()["action_id"])


def test_a_code_opens_one_session_and_only_once(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    code = c.post("/v1/console/code", headers=AGENT).json()["code"]
    first = c.post("/v1/console/session", json={"code": code})
    again = c.post("/v1/console/session", json={"code": code})
    assert first.status_code == 200 and again.status_code == 401
    session = {"Authorization": f"Bearer {first.json()['token']}"}
    assert c.get("/v1/events", headers=session).status_code == 200
    assert first.json()["token"] != TOKEN


def test_an_expired_code_is_refused() -> None:
    now = [0.0]
    s = sessions_mod.ConsoleSessions(clock=lambda: now[0])
    code = s.new_code()
    assert code
    now[0] = sessions_mod.CODE_SECONDS + 1
    assert s.redeem(code) is None


def test_a_session_ends_after_its_time_and_on_sign_out() -> None:
    now = [0.0]
    s = sessions_mod.ConsoleSessions(clock=lambda: now[0])
    a, b = s.open(), s.open()
    assert a and b and s.valid(a) and s.valid(b)
    s.close(a)
    assert not s.valid(a) and s.valid(b)
    now[0] = sessions_mod.SESSION_SECONDS + 1
    assert not s.valid(b)


def test_a_flood_of_codes_is_refused_not_stored() -> None:
    s = sessions_mod.ConsoleSessions(clock=lambda: 0.0)
    codes = [s.new_code() for _ in range(sessions_mod.MAX_LIVE + 5)]
    assert codes.count(None) == 5


def test_the_api_token_typed_at_sign_in_becomes_a_session(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    r = c.post("/v1/console/session", json={}, headers=AGENT)
    assert r.status_code == 200 and r.json()["token"] != TOKEN
    wrong = c.post("/v1/console/session", json={}, headers={"Authorization": "Bearer " + "x" * 30})
    assert wrong.status_code == 401


def test_a_console_session_cannot_mint_codes(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    assert c.post("/v1/console/code", headers=console(c)).status_code == 403


def test_a_console_session_cannot_claim_policy(world: tuple[TestClient, Any]) -> None:
    c, engine = world
    action = pending(c)
    r = c.post(f"/v1/actions/{action}/approve", headers=console(c) | {"X-Lynceus-Actor": "policy"})
    assert r.status_code == 200
    got = c.get(f"/v1/actions/{action}", headers=AGENT).json()
    assert got["decided_by"] == "user"
    with engine.connect() as conn:
        actors = {a for (a,) in conn.execute(select(db.AuditLog.actor))}
    assert "policy" in actors  # the proposal itself, by policy
    approvals = [
        r for r in c.get("/v1/audit", headers=AGENT).json() if r["action"].endswith("approve")
    ]
    assert approvals and all(r["actor"] == "user" for r in approvals)


def test_the_agent_may_still_act_as_policy(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    action = pending(c)
    r = c.post(f"/v1/actions/{action}/approve", headers=AGENT | {"X-Lynceus-Actor": "policy"})
    assert r.status_code == 200
    assert c.get(f"/v1/actions/{action}", headers=AGENT).json()["decided_by"] == "policy"


def test_a_console_session_cannot_report_what_the_agent_did(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    action = pending(c)
    session = console(c)
    c.post(f"/v1/actions/{action}/approve", headers=session)
    r = c.post(f"/v1/actions/{action}/result", json={"outcome": "applied"}, headers=session)
    assert r.status_code == 403
    assert c.get(f"/v1/actions/{action}", headers=AGENT).json()["state"] == "APPROVED"


def test_sign_out_ends_the_session(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    session = console(c)
    assert c.delete("/v1/console/session", headers=session).status_code == 200
    assert c.get("/v1/events", headers=session).status_code == 401


def test_sign_ins_and_failures_are_audited_without_secrets(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    console(c)
    c.post("/v1/console/session", json={"code": "z" * 40})
    rows = c.get("/v1/audit", headers=AGENT).json()
    signed = [r for r in rows if r["action"] == "console.sign_in"]
    assert signed and signed[0]["detail"] == {"with": "code"}
    assert TOKEN not in str(rows) and "z" * 40 not in str(rows)


def test_unknown_session_tokens_are_refused(world: tuple[TestClient, Any]) -> None:
    c, _ = world
    fake = {"Authorization": f"Bearer {uuid.uuid4().hex}"}
    assert c.get("/v1/events", headers=fake).status_code == 401
