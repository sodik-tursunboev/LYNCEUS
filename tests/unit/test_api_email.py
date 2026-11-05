"""POST /v1/emails/analyze: raw message in, verdict out. The sandbox is replaced by the in-process
parser except in the one test that says otherwise."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from mailhelp import PHISH_LINK, eml, in_process
from sqlalchemy import create_engine, func, select

from core import sandbox
from core.api.app import create_app
from core.config import Settings
from core.contracts import Verdict
from core.db import models as db
from core.email import engine

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PATH = "/v1/emails/analyze"
RFC822 = {"Content-Type": "message/rfc822"}
PHISH = eml(sender='"PayPal Support" <help@paypal-login.test>', subject="Urgent", html=PHISH_LINK)


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "run_sandbox", in_process)


def client(**over: Any) -> TestClient:
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def post(c: TestClient, raw: bytes, **headers: str) -> Any:
    return c.post(PATH, content=raw, headers=AUTH | RFC822 | headers)


def test_a_phishing_message_gets_a_full_verdict() -> None:
    r = post(client(), PHISH)
    assert r.status_code == 200
    body = r.json()
    Verdict.model_validate(body["verdict"])
    assert body["verdict"]["state"] in ("SUSPICIOUS", "MALICIOUS")
    assert body["verdict"]["applied_response"] == "NONE"
    assert body["persisted"] is False and body["reason"] is None
    assert body["summary"]["parts"] >= 1 and body["summary"]["links"] >= 1
    assert {e["id"] for e in body["evidence"]} == set(body["verdict"]["evidence_ids"])


def test_a_message_with_no_signals_is_unknown() -> None:
    v = post(client(), eml()).json()["verdict"]
    assert (v["state"], v["risk_score"]) == ("UNKNOWN", None)


@pytest.mark.parametrize(
    "ctype", ["message/rfc822", "MESSAGE/RFC822; charset=utf-8", "application/octet-stream"]
)
def test_accepted_content_types(ctype: str) -> None:
    assert post(client(), eml(), **{"Content-Type": ctype}).status_code == 200


@pytest.mark.parametrize("ctype", ["application/json", "text/plain", "multipart/form-data", ""])
def test_other_content_types_are_415(ctype: str) -> None:
    assert post(client(), eml(), **{"Content-Type": ctype}).status_code == 415


def test_an_empty_body_is_a_verdict_not_a_failure() -> None:
    body = post(client(), b"").json()
    assert (body["verdict"]["state"], body["reason"]) == ("UNKNOWN", "empty")


def test_the_sandbox_being_down_is_an_error_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_raw: bytes) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("not built")

    monkeypatch.setattr(engine, "run_sandbox", unavailable)
    r = post(client(), eml())
    assert r.status_code == 200
    assert (r.json()["verdict"]["state"], r.json()["reason"]) == ("ERROR", "sandbox_unavailable")


# ---- limits and access ---------------------------------------------------------------------------


def test_the_message_cap_is_separate_from_the_url_cap() -> None:
    c = client(max_body_bytes=100, max_message_bytes=100_000)
    assert post(c, PHISH).status_code == 200  # over 100 bytes, under the message cap
    assert c.post("/v1/urls/analyze", json={"url": "a" * 200}, headers=AUTH).status_code == 413


def test_body_over_the_message_cap_is_413_with_a_declared_length() -> None:
    assert post(client(max_message_bytes=500), eml(text="x" * 2000)).status_code == 413


def test_body_over_the_message_cap_is_413_when_chunked() -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b"A" * 100

    r = client(max_message_bytes=500).post(PATH, content=chunks(), headers=AUTH | RFC822)
    assert r.status_code == 413


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic x"}]
)
def test_bad_or_missing_token_is_401(headers: dict[str, str]) -> None:
    r = client().post(PATH, content=eml(), headers=RFC822 | headers)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_no_configured_token_means_no_service() -> None:
    c = TestClient(create_app(Settings(_env_file=None)), base_url="http://127.0.0.1")
    assert c.post(PATH, content=eml(), headers=AUTH | RFC822).status_code == 503


def test_the_rate_limit_is_shared_with_the_url_route() -> None:
    c = client(rate_limit_per_minute=2)
    assert (
        c.post("/v1/urls/analyze", json={"url": "https://example.test/"}, headers=AUTH).status_code
        == 200
    )
    assert post(c, eml()).status_code == 200
    r = post(c, eml())
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_busy_parsers_get_503_with_retry_after() -> None:
    r = post(client(max_concurrent_parsers=0), eml())  # no slot can ever be taken
    assert r.status_code == 503 and r.headers["retry-after"] == "2"


def test_a_slot_is_released_after_each_request() -> None:
    c = client(max_concurrent_parsers=1)
    assert [post(c, eml()).status_code for _ in range(3)] == [200, 200, 200]


def test_a_slot_is_released_after_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_raw: bytes) -> sandbox.Result:
        raise RuntimeError("bug")

    c = client(max_concurrent_parsers=1)
    monkeypatch.setattr(engine, "run_sandbox", boom)
    body = post(c, eml()).json()
    assert (body["verdict"]["state"], body["reason"]) == ("ERROR", "sandbox_error")
    monkeypatch.setattr(engine, "run_sandbox", in_process)
    assert post(c, eml()).status_code == 200


def test_the_route_is_documented_as_a_raw_message_body() -> None:
    spec = create_app(Settings(_env_file=None)).openapi()
    body = spec["paths"][PATH]["post"]["requestBody"]
    assert "message/rfc822" in body["content"]


# ---- storage -------------------------------------------------------------------------------------


def sqlite_url(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    db.Base.metadata.create_all(create_engine(url))
    return url


def test_the_verdict_is_stored_by_hash_and_host_never_by_text(tmp_path: Path) -> None:
    url = sqlite_url(tmp_path)
    raw = eml(
        sender='"PayPal Support" <help@paypal-login.test>',
        subject="SUBJMARK",
        text="BODYMARK",
        html='<a href="https://paypal-login.test/PATHMARK?q=QUERYMARK">https://www.paypal.com/x</a>',
        attachments=[("FILEMARK.pdf.exe", b"MZ\x90\x00", "application/octet-stream")],
    )
    r = post(client(database_url=url), raw)
    assert r.status_code == 200 and r.json()["persisted"] is True
    engine_ = create_engine(url)
    with engine_.connect() as c:
        dump = "\n".join(
            repr(row) for t in db.Base.metadata.sorted_tables for row in c.execute(select(t))
        )
        assert c.scalar(select(func.count()).select_from(db.Verdict)) == 1
        kinds = set(c.scalars(select(db.Artifact.kind)))
        urls = c.execute(select(db.ExtractedUrl)).all()
    assert kinds == {"EMAIL"} and urls and all(u.url is None for u in urls)
    for marker in (
        "SUBJMARK",
        "BODYMARK",
        "PATHMARK",
        "QUERYMARK",
        "FILEMARK",
        "PayPal Support",
        "help@",
    ):
        assert marker not in dump, marker


def test_a_storage_failure_does_not_cost_the_caller_the_verdict(tmp_path: Path) -> None:
    broken = f"sqlite:///{tmp_path / 'missing' / 'nope.db'}"
    r = post(client(database_url=broken), PHISH)
    assert r.status_code == 200 and r.json()["persisted"] is False
    assert r.json()["verdict"]["state"] in ("SUSPICIOUS", "MALICIOUS")
