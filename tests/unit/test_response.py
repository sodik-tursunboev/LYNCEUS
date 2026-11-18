"""The response engine's core side (M6): a state machine that cannot be forced, actions that are
proposed only for stored MALICIOUS verdicts, every change audited, nothing about a file's name or
location stored. The sandbox is the in-process guest scanner; the database is a throwaway SQLite."""

import hashlib
import itertools
import json
import threading
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

import filehelp as fh
import pytest
from fastapi.testclient import TestClient
from mailhelp import HOSTS_SEALED, in_process_file
from sqlalchemy import create_engine, select

from core.api.app import create_app
from core.config import Settings
from core.db import models as db
from core.files import engine as file_engine
from core.response import service
from core.response.machine import ALREADY, NEXT, Event, step

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
EXE = b"MZ\x90\x00" + b"\x00" * 60
BAD_PDF = fh.make_pdf(
    "/OpenAction 4 0 R",
    [
        "<< /S /Launch /F (cmd.exe) >>",
        "<< /S /JavaScript /JS (x) >>",
        "<< /S /URI /URI (https://paypal-login.test/login.php?email=jane%40example.test) >>",
    ],
)  # MALICIOUS: three independent kinds of evidence
STATES = ["PENDING", "APPROVED", "APPLIED", "DISMISSED", "FAILED", "RESTORE_REQUESTED", "RESTORED"]


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_engine, "run_inspect_bytes", in_process_file)


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.url = f"sqlite:///{tmp_path / 'lynceus.db'}"
        self.engine = create_engine(self.url)
        db.Base.metadata.create_all(self.engine)
        settings = Settings(
            _env_file=None, api_token=TOKEN, database_url=self.url, data_dir=tmp_path / "data"
        )
        self.client = TestClient(create_app(settings), base_url="http://127.0.0.1")

    def send(self, name: str, data: bytes, ref: str | None = "a" * 32) -> Any:
        h = AUTH | {
            "Content-Type": "application/octet-stream",
            "X-Lynceus-Name": quote(name, safe=""),
        }
        if ref:
            h["X-Lynceus-File-Id"] = ref
        return self.client.post("/v1/files/analyze", content=data, headers=h)

    def act(self, action_id: str, verb: str, actor: str | None = None) -> Any:
        headers = AUTH | ({"X-Lynceus-Actor": actor} if actor else {})
        return self.client.post(f"/v1/actions/{action_id}/{verb}", headers=headers)

    def result(self, action_id: str, outcome: str, reason: str | None = None) -> Any:
        body = {"outcome": outcome} | ({"reason": reason} if reason else {})
        return self.client.post(f"/v1/actions/{action_id}/result", json=body, headers=AUTH)

    def pending(self) -> str:
        r = self.send("PRIVATENAME-statement.pdf", BAD_PDF)
        assert r.status_code == 200 and r.json()["verdict"]["state"] == "MALICIOUS", r.text
        action_id = r.json()["action_id"]
        assert action_id
        return str(action_id)

    def state(self, action_id: str) -> str:
        return str(self.client.get(f"/v1/actions/{action_id}", headers=AUTH).json()["state"])

    def audit_actions(self) -> list[str]:
        rows = self.client.get("/v1/audit?limit=500", headers=AUTH).json()
        return [r["action"] for r in reversed(rows)]


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


# ---- the state machine -----------------------------------------------------------------------


@pytest.mark.parametrize(("state", "event"), list(itertools.product(STATES, Event)))
def test_every_state_and_event_has_exactly_one_stated_outcome(state: str, event: Event) -> None:
    s = step(state, event)
    if (state, event) in NEXT:
        assert (s.new_state, s.changed, s.legal) == (NEXT[(state, event)], True, True)
    elif state in ALREADY[event]:
        assert (s.new_state, s.changed, s.legal) == (state, False, True)
    else:
        assert (s.new_state, s.changed, s.legal) == (state, False, False)


@pytest.mark.parametrize(("state", "event"), [k for k in NEXT])
def test_repeating_an_event_never_changes_anything_a_second_time(state: str, event: Event) -> None:
    first = step(state, event)
    again = step(first.new_state, event)
    assert not again.changed and again.legal or event is Event.RESTORE_FAILED


def test_a_file_can_only_be_applied_after_it_was_approved_and_restored_after_it_was_applied() -> (
    None
):
    assert not step("PENDING", Event.APPLIED).legal
    assert step("DISMISSED", Event.APPLIED) == ("APPLIED", True, True)  # a fact, see the race test
    assert not step("PENDING", Event.RESTORE).legal
    assert not step("APPROVED", Event.RESTORE).legal
    assert not step("RESTORED", Event.APPROVE).changed


def test_no_event_exists_that_deletes() -> None:
    assert {e.value for e in Event} == {
        "approve", "dismiss", "restore", "applied", "failed", "restored", "restore_failed",
    }  # fmt: skip


# ---- proposing an action -----------------------------------------------------------------------


def test_a_malicious_file_gets_a_pending_action_and_a_suspicious_one_does_not(world: World) -> None:
    mild = world.send("invoice.pdf.exe", EXE, "b" * 32).json()
    assert mild["verdict"]["state"] == "SUSPICIOUS" and mild["action_id"] is None
    action_id = world.pending()
    got = world.client.get(f"/v1/actions/{action_id}", headers=AUTH).json()
    assert (got["state"], got["kind"], got["verdict_state"]) == (
        "PENDING",
        "FILE_QUARANTINE",
        "MALICIOUS",
    )
    assert got["decided_by"] is None and got["file_ref"] == "a" * 32


def test_no_file_id_means_no_action_and_a_malformed_one_is_ignored(world: World) -> None:
    assert world.send("a.pdf", BAD_PDF, None).json()["action_id"] is None
    r = world.client.post(
        "/v1/files/analyze", content=BAD_PDF,
        headers=AUTH | {"Content-Type": "application/octet-stream", "X-Lynceus-Name": "a.pdf",
                        "X-Lynceus-File-Id": "not-hex"},
    )  # fmt: skip
    assert r.status_code == 200 and r.json()["action_id"] is None


def test_the_same_file_sent_twice_has_one_action(world: World) -> None:
    first = world.pending()
    again = world.send("x.pdf", BAD_PDF).json()["action_id"]
    assert again == first
    assert len(world.client.get("/v1/actions", headers=AUTH).json()) == 1


def test_two_copies_of_the_same_bytes_are_two_actions(world: World) -> None:
    a = world.send("one.pdf", BAD_PDF, "1" * 32).json()["action_id"]
    b = world.send("two.pdf", BAD_PDF, "2" * 32).json()["action_id"]
    assert a and b and a != b


def test_an_allow_listed_file_is_not_proposed_and_the_response_says_so(world: World) -> None:
    sha = (
        fh.hashlib.sha256(BAD_PDF).hexdigest()
        if hasattr(fh, "hashlib")
        else __import__("hashlib").sha256(BAD_PDF).hexdigest()
    )
    added = world.client.post("/v1/allowlist", json={"sha256": sha, "days": 30}, headers=AUTH)
    assert added.status_code == 200 and added.json()["expires_at"] is not None
    r = world.send("a.pdf", BAD_PDF).json()
    assert (r["action_id"], r["allow_listed"], r["verdict"]["state"]) == (None, True, "MALICIOUS")
    assert world.client.delete(f"/v1/allowlist/{sha}", headers=AUTH).json() == {"removed": True}
    assert world.client.delete(f"/v1/allowlist/{sha}", headers=AUTH).json() == {"removed": False}
    assert world.send("a.pdf", BAD_PDF).json()["action_id"] is not None


def test_an_expired_allow_entry_no_longer_counts(world: World) -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update

    sha = hashlib.sha256(BAD_PDF).hexdigest()
    world.client.post("/v1/allowlist", json={"sha256": sha, "days": 1}, headers=AUTH)
    with world.engine.begin() as c:
        c.execute(update(db.Allow).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    assert service.allow_listed(world.engine, sha) is False
    assert world.client.get("/v1/allowlist", headers=AUTH).json() == []


# ---- the life of an action ---------------------------------------------------------------------


def test_the_whole_life_with_every_step_audited_and_repeats_changing_nothing(world: World) -> None:
    a = world.pending()
    assert world.act(a, "approve").json() == {"id": a, "state": "APPROVED", "changed": True}
    assert world.act(a, "approve").json()["changed"] is False
    assert world.result(a, "applied").json()["state"] == "APPLIED"
    assert world.result(a, "applied").json()["changed"] is False
    assert world.act(a, "restore").json()["state"] == "RESTORE_REQUESTED"
    assert world.act(a, "restore").json()["changed"] is False
    assert world.result(a, "restored").json()["state"] == "RESTORED"
    assert world.result(a, "restored").json()["changed"] is False
    assert world.audit_actions() == [
        "action.create", "action.approve", "action.applied", "action.restore", "action.restored",
    ]  # fmt: skip
    final = world.client.get(f"/v1/actions/{a}", headers=AUTH).json()
    assert final["decided_by"] == "user" and final["finished_at"] and final["decided_at"]


def test_a_state_cannot_be_forced(world: World) -> None:
    a = world.pending()
    assert (
        world.result(a, "applied").status_code == 409
    )  # the agent cannot act on an unapproved action
    assert world.act(a, "restore").status_code == 409
    world.act(a, "approve")
    assert world.act(a, "dismiss").json()["state"] == "DISMISSED"
    assert world.act(a, "approve").json()["state"] == "APPROVED"  # a change of mind is allowed
    world.result(a, "applied")
    assert (
        world.act(a, "dismiss").status_code == 409
    )  # a quarantined file is restored, not dismissed
    assert world.state(a) == "APPLIED"


def test_a_file_the_agent_had_already_moved_when_you_dismissed_can_still_be_restored(
    world: World,
) -> None:
    a = world.pending()
    world.act(a, "approve")
    assert world.act(a, "dismiss").json()["state"] == "DISMISSED"  # you changed your mind ...
    # ... but the agent had already moved the file: its report is a fact and must not be lost
    assert world.result(a, "applied").json()["state"] == "APPLIED"
    assert world.act(a, "restore").json()["state"] == "RESTORE_REQUESTED"


def test_a_failure_is_stated_and_can_be_retried_and_a_failed_restore_keeps_the_file_quarantined(
    world: World,
) -> None:
    a = world.pending()
    world.act(a, "approve")
    assert world.result(a, "failed", "file_locked").json()["state"] == "FAILED"
    assert world.client.get(f"/v1/actions/{a}", headers=AUTH).json()["reason"] == "file_locked"
    assert world.act(a, "approve").json()["state"] == "APPROVED"
    world.result(a, "applied")
    world.act(a, "restore")
    assert world.result(a, "restore_failed", "name_taken").json()["state"] == "APPLIED"
    assert world.client.get(f"/v1/actions/{a}", headers=AUTH).json()["reason"] == "name_taken"
    assert world.act(a, "restore").json()["state"] == "RESTORE_REQUESTED"


def test_an_unknown_action_is_a_404_and_a_bad_result_a_422(world: World) -> None:
    ghost = str(uuid.uuid4())
    assert world.act(ghost, "approve").status_code == 404
    assert world.result(ghost, "applied").status_code == 404
    a = world.pending()
    for body in (
        {"outcome": "deleted"},
        {"outcome": "applied", "reason": "../../x"},
        {"outcome": "applied", "x": 1},
        {},
    ):
        assert (
            world.client.post(f"/v1/actions/{a}/result", json=body, headers=AUTH).status_code == 422
        )
    assert world.client.post("/v1/actions/not-a-uuid/approve", headers=AUTH).status_code == 422


def test_two_callers_approving_at_once_change_it_exactly_once(world: World) -> None:
    a = uuid.UUID(world.pending())
    outcomes: list[bool] = []

    def go() -> None:
        outcomes.append(service.transition(world.engine, a, Event.APPROVE, "user").changed)

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == [False] * 5 + [True]
    assert world.audit_actions().count("action.approve") == 1


def test_the_policy_actor_is_recorded_but_an_invented_one_is_not(world: World) -> None:
    a = world.pending()
    world.act(a, "approve", actor="policy")
    assert world.client.get(f"/v1/actions/{a}", headers=AUTH).json()["decided_by"] == "policy"
    rows = world.client.get("/v1/audit", headers=AUTH).json()
    assert {r["actor"] for r in rows} <= {"user", "policy", "agent"}
    b = world.send("b.pdf", BAD_PDF, "c" * 32).json()["action_id"]
    world.act(b, "approve", actor="root")
    assert world.client.get(f"/v1/actions/{b}", headers=AUTH).json()["decided_by"] == "user"


# ---- reading ---------------------------------------------------------------------------------


def test_events_list_and_detail_carry_evidence_and_link_to_the_action(world: World) -> None:
    world.send("invoice.pdf.exe", EXE, "b" * 32)
    a = world.pending()
    events = world.client.get("/v1/events?limit=10", headers=AUTH).json()
    assert {e["state"] for e in events} == {"SUSPICIOUS", "MALICIOUS"}
    bad = next(e for e in events if e["state"] == "MALICIOUS")
    assert (
        bad["action_id"] == a
        and bad["action_state"] == "PENDING"
        and "email.pdf_launch_action" in bad["rules"]
    )
    only = world.client.get("/v1/events?state=SUSPICIOUS", headers=AUTH).json()
    assert [e["state"] for e in only] == ["SUSPICIOUS"]
    detail = world.client.get(f"/v1/events/{bad['id']}", headers=AUTH).json()
    assert detail["signals"] and detail["evidence"] and detail["explanation"]
    assert world.client.get(f"/v1/events/{uuid.uuid4()}", headers=AUTH).status_code == 404


def test_the_audit_list_is_bounded_and_newest_first(world: World) -> None:
    a = world.pending()
    world.act(a, "approve")
    rows = world.client.get("/v1/audit?limit=1", headers=AUTH).json()
    assert [r["action"] for r in rows] == ["action.approve"]
    assert world.client.get("/v1/audit?limit=0", headers=AUTH).status_code == 422
    assert world.client.get("/v1/audit?limit=501", headers=AUTH).status_code == 422


# ---- guards and privacy ------------------------------------------------------------------------


ROUTES = [
    ("GET", "/v1/events"), ("GET", f"/v1/events/{uuid.uuid4()}"), ("GET", "/v1/actions"),
    ("GET", f"/v1/actions/{uuid.uuid4()}"), ("POST", f"/v1/actions/{uuid.uuid4()}/approve"),
    ("POST", f"/v1/actions/{uuid.uuid4()}/dismiss"),
    ("POST", f"/v1/actions/{uuid.uuid4()}/restore"),
    ("GET", "/v1/allowlist"), ("GET", "/v1/audit"),
]  # fmt: skip


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_every_response_route_needs_the_token(world: World, method: str, path: str) -> None:
    assert world.client.request(method, path).status_code == 401


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_without_a_database_the_routes_say_so(tmp_path: Path, method: str, path: str) -> None:
    c = TestClient(
        create_app(Settings(_env_file=None, api_token=TOKEN)), base_url="http://127.0.0.1"
    )
    assert c.request(method, path, headers=AUTH).status_code == 503


def test_without_a_database_a_malicious_file_still_gets_its_verdict_and_no_action(
    tmp_path: Path,
) -> None:
    c = TestClient(
        create_app(Settings(_env_file=None, api_token=TOKEN)), base_url="http://127.0.0.1"
    )
    r = c.post(
        "/v1/files/analyze", content=BAD_PDF,
        headers=AUTH | {"Content-Type": "application/octet-stream", "X-Lynceus-Name": "a.pdf",
                        "X-Lynceus-File-Id": "a" * 32},
    )  # fmt: skip
    assert r.status_code == 200 and r.json()["verdict"]["state"] == "MALICIOUS"
    assert r.json()["action_id"] is None and r.json()["persisted"] is False


def test_nothing_about_a_name_or_a_location_is_stored(world: World) -> None:
    a = world.pending()
    world.act(a, "approve")
    world.result(a, "failed", "file_locked")
    with world.engine.connect() as c:
        dump = "\n".join(
            repr(row) for t in db.Base.metadata.sorted_tables for row in c.execute(select(t))
        )
    names = ["PRIVATENAME", "statement.pdf", "jane", "C:\\"]
    if HOSTS_SEALED:
        names.append("paypal-login.test")  # H1 A8: even the host of a link is stored only sealed
    for private in names:
        assert private not in dump, private
    detail = world.client.get("/v1/events", headers=AUTH).json()[0]
    shown = world.client.get(f"/v1/events/{detail['id']}", headers=AUTH).json()
    assert "paypal-login.test" in json.dumps(shown)  # ... and read back for you, through the API


def test_the_audit_detail_has_a_hash_prefix_and_states_not_content(world: World) -> None:
    a = world.pending()
    world.act(a, "approve")
    detail = world.client.get("/v1/audit?limit=1", headers=AUTH).json()[0]["detail"]
    assert set(detail) == {"sha12", "from", "to", "reason"} and len(detail["sha12"]) == 12
    json.dumps(detail)


def test_proposing_for_an_allow_listed_file_returns_nothing_even_when_called_directly(
    world: World,
) -> None:
    r = world.send("a.pdf", BAD_PDF, "d" * 32).json()
    verdict_id = uuid.UUID(r["verdict"]["id"])
    sha = hashlib.sha256(BAD_PDF).hexdigest()
    service.allow_add(world.engine, sha, "user", None)
    assert service.create_pending(world.engine, verdict_id, "e" * 32, sha) is None
    assert (
        service.create_pending(world.engine, verdict_id, "d" * 32, sha) is not None
    )  # the earlier one stays


def test_the_service_never_stores_an_actor_it_does_not_know(world: World) -> None:
    a = uuid.UUID(world.pending())
    service.transition(world.engine, a, Event.APPROVE, "root")
    assert world.client.get(f"/v1/actions/{a}", headers=AUTH).json()["decided_by"] == "user"
