"""Randomised attack on the response routes (M7): whatever is sent, the server answers with a stated
status, never an unhandled error, and the database never holds a state the machine forbids. The seed
is fixed so a failure reproduces."""

import random
import string
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select

from core.api.app import create_app
from core.config import Settings
from core.db import models as db
from core.response import service
from core.response.machine import Event

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
OK = {200, 404, 409, 413, 422}
ALPHABET = string.printable + "éß€\u202e\u0000\ud7ff漢字😀"


def junk(rng: random.Random, n: int = 20) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, n)))


def value(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randint(0, 6 if depth < 2 else 3)
    if kind == 0:
        return junk(rng)
    if kind == 1:
        return rng.choice([0, -1, 1, 2**63, -(2**63), 3.5, float("1e308")])
    if kind == 2:
        return rng.choice([None, True, False])
    if kind == 3:
        return str(uuid.UUID(int=rng.getrandbits(128)))
    if kind == 4:
        return [value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {junk(rng, 6): value(rng, depth + 1) for _ in range(rng.randint(0, 3))}


@pytest.fixture
def world(tmp_path: Path) -> tuple[TestClient, Any]:
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    engine = create_engine(url)
    db.Base.metadata.create_all(engine)
    settings = Settings(
        _env_file=None,
        api_token=TOKEN,
        database_url=url,
        data_dir=tmp_path,
        rate_limit_per_minute=10**6,
    )
    return TestClient(create_app(settings), base_url="http://127.0.0.1"), engine


def test_random_requests_to_every_response_route_get_a_stated_answer(world: Any) -> None:
    client, engine = world
    rng = random.Random(20261105)
    seen: set[int] = set()
    for _ in range(600):
        ident = quote(
            rng.choice([str(uuid.UUID(int=rng.getrandbits(128))), junk(rng, 10), "../x", "0" * 40]),
            safe="",
        )
        route = rng.choice(
            [
                ("GET", f"/v1/actions/{ident}"), ("POST", f"/v1/actions/{ident}/approve"),
                ("POST", f"/v1/actions/{ident}/dismiss"), ("POST", f"/v1/actions/{ident}/restore"),
                ("POST", f"/v1/actions/{ident}/result"), ("GET", f"/v1/events/{ident}"),
                ("GET", "/v1/actions"), ("GET", "/v1/events"), ("GET", "/v1/audit"),
                ("GET", "/v1/allowlist"), ("POST", "/v1/allowlist"),
                ("DELETE", f"/v1/allowlist/{ident}"),
            ]
        )  # fmt: skip
        params = {
            rng.choice(["state", "limit", "x"]): junk(rng, 8) for _ in range(rng.randint(0, 2))
        }
        headers = AUTH | {"X-Mirage-Actor": junk(rng, 8).encode("ascii", "ignore").decode()}
        body = value(rng) if route[0] == "POST" else None
        r = client.request(
            route[0], route[1].replace("\x00", ""), params=params, headers=headers, json=body
        )
        seen.add(r.status_code)
        assert r.status_code in OK, (route, params, body, r.status_code, r.text[:200])
        r.json()
    assert {200, 404, 422} <= seen


def test_random_events_on_real_actions_never_leave_a_forbidden_state(world: Any) -> None:
    client, engine = world
    rng = random.Random(7)
    with engine.begin() as c:
        from sqlalchemy import insert

        artifact, event, verdict = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        c.execute(insert(db.Event).values(id=event, source="AGENT", observed_at=db.func.now()))
        c.execute(
            insert(db.Artifact).values(
                id=artifact, event_id=event, kind="FILE", sha256="a" * 64, ref="x"
            )
        )
        c.execute(
            insert(db.Verdict).values(
                id=verdict, artifact_id=artifact, state="MALICIOUS", risk_score=90,
                confidence="HIGH",
                recommended_response="QUARANTINE", applied_response="NONE", explanation="t",
                engine_version="t", ruleset_version="t",
            )
        )  # fmt: skip
    ids = [service.create_pending(engine, verdict, f"{i:032x}", "a" * 64) for i in range(5)]
    assert all(ids)
    history: list[tuple[str, str, str]] = []
    for _ in range(500):
        a = rng.choice(ids)
        event_name = rng.choice(list(Event))
        before = service.get_action(engine, a)["state"]  # type: ignore[index]
        t = service.transition(
            engine, a, event_name, rng.choice(["user", "policy", "agent", "root"])
        )
        after = service.get_action(engine, a)["state"]  # type: ignore[index]
        history.append((before, event_name.value, after))
        assert t.legal or before == after
    legal_pairs = {
        (s, e.value) for (s, e) in __import__("core.response.machine", fromlist=["NEXT"]).NEXT
    }
    for before, ev, after in history:
        assert before == after or (before, ev) in legal_pairs, (before, ev, after)
    with engine.connect() as c:
        states = {r.state for r in c.execute(select(db.Action))}
        actors = {r.actor for r in c.execute(select(db.AuditLog))}
    assert states <= set(db.ACTION_STATES)
    assert actors <= {"user", "policy", "agent"}


def test_the_console_route_never_serves_outside_its_folder_or_errors(tmp_path: Path) -> None:
    site = tmp_path / "dist"
    site.mkdir()
    (site / "index.html").write_text("<title>c</title>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOP SECRET", encoding="utf-8")
    settings = Settings(_env_file=None, api_token=TOKEN, console_dir=site, data_dir=tmp_path)
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    rng = random.Random(3)
    pieces = [
        "..",
        "%2e%2e",
        "%2f",
        "%5c",
        ".",
        "secret.txt",
        "index.html",
        "%00",
        "con",
        "nul",
        "~1",
        "::$DATA",
    ]
    for _ in range(300):
        path = "/console/" + "/".join(rng.choice(pieces) for _ in range(rng.randint(1, 6)))
        r = client.get(path)
        assert r.status_code < 500, (path, r.status_code)
        assert "TOP SECRET" not in r.text, path
