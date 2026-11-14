"""H1 B3: "this verdict was wrong" from the console or the browser's warning page becomes a stored,
audited label, and the rules behind false alarms are counted per rule."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from core.api.app import create_app
from core.config import Settings
from core.db import models as db

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AGENT = {"Authorization": f"Bearer {TOKEN}"}
LOOKALIKE = "https://paypal-login.test/login.php?email=jane%40example.test"


@pytest.fixture
def c(tmp_path: Path) -> TestClient:
    url = f"sqlite:///{tmp_path / 'lynceus.db'}"
    db.Base.metadata.create_all(create_engine(url))
    settings = Settings(_env_file=None, api_token=TOKEN, database_url=url, data_dir=tmp_path / "d")
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def console(c: TestClient) -> dict[str, str]:
    code = c.post("/v1/console/code", headers=AGENT).json()["code"]
    return {
        "Authorization": "Bearer "
        + c.post("/v1/console/session", json={"code": code}).json()["token"]
    }


def flagged_event(c: TestClient, url: str = LOOKALIKE) -> tuple[str, list[str]]:
    r = c.post("/v1/urls/analyze", json={"url": url}, headers=AGENT)
    assert r.json()["persisted"] and r.json()["verdict"]["state"] in ("SUSPICIOUS", "MALICIOUS")
    event = c.get("/v1/events", headers=AGENT).json()[0]
    return event["id"], event["rules"]


def test_a_false_alarm_from_the_console_is_stored_audited_and_counted_per_rule(
    c: TestClient,
) -> None:
    verdict, rules = flagged_event(c)
    session = console(c)
    assert (
        c.post(
            f"/v1/events/{verdict}/feedback", json={"label": "false_alarm"}, headers=session
        ).status_code
        == 200
    )
    assert c.get(f"/v1/events/{verdict}", headers=session).json()["feedback"] == "false_alarm"
    counts = {r["rule_id"]: r for r in c.get("/v1/feedback/rules", headers=session).json()}
    assert set(rules) <= set(counts) and all(counts[r]["false_alarm"] == 1 for r in rules)
    audit = [a["action"] for a in c.get("/v1/audit", headers=AGENT).json()]
    assert "feedback.false_alarm" in audit


def test_the_latest_answer_replaces_the_earlier_one(c: TestClient) -> None:
    verdict, rules = flagged_event(c)
    session = console(c)
    for label in ("false_alarm", "correct"):
        c.post(f"/v1/events/{verdict}/feedback", json={"label": label}, headers=session)
    counts = {r["rule_id"]: r for r in c.get("/v1/feedback/rules", headers=session).json()}
    assert all((counts[r]["false_alarm"], counts[r]["correct"]) == (0, 1) for r in rules)


@pytest.mark.parametrize("body", [{"label": "safe"}, {"label": "false_alarm", "extra": 1}, {}])
def test_a_bad_label_is_refused(c: TestClient, body: dict[str, Any]) -> None:
    verdict, _ = flagged_event(c)
    assert (
        c.post(f"/v1/events/{verdict}/feedback", json=body, headers=console(c)).status_code == 422
    )


def test_an_unknown_event_and_the_policy_cannot_give_feedback(c: TestClient) -> None:
    verdict, _ = flagged_event(c)
    missing = "00000000-0000-0000-0000-000000000000"
    assert (
        c.post(
            f"/v1/events/{missing}/feedback", json={"label": "correct"}, headers=console(c)
        ).status_code
        == 404
    )
    policy = AGENT | {"X-Lynceus-Actor": "policy"}
    assert (
        c.post(
            f"/v1/events/{verdict}/feedback", json={"label": "correct"}, headers=policy
        ).status_code
        == 403
    )


def test_continue_and_report_on_the_warning_page_marks_the_verdict_a_false_alarm(
    c: TestClient,
) -> None:
    verdict, _ = flagged_event(c)
    r = c.post(
        "/v1/overrides",
        json={"url": LOOKALIKE, "state": "SUSPICIOUS", "mistake": True},
        headers=AGENT,
    )
    assert r.status_code == 200 and r.json()["reported_false_alarm"] is True
    assert c.get(f"/v1/events/{verdict}", headers=AGENT).json()["feedback"] == "false_alarm"


def test_a_plain_continue_is_not_a_report(c: TestClient) -> None:
    verdict, _ = flagged_event(c)
    r = c.post("/v1/overrides", json={"url": LOOKALIKE, "state": "SUSPICIOUS"}, headers=AGENT)
    assert r.json()["reported_false_alarm"] is False
    assert c.get(f"/v1/events/{verdict}", headers=AGENT).json()["feedback"] is None


def test_a_report_for_a_url_never_judged_records_nothing(c: TestClient) -> None:
    r = c.post(
        "/v1/overrides", json={"url": "https://never-seen.test/", "mistake": True}, headers=AGENT
    )
    assert r.status_code == 200 and r.json()["reported_false_alarm"] is False
