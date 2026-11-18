"""Intelligence through the API: the verdict never depends on a provider, failures are stated,
persistence keeps provider results, the health endpoint says what is enabled, and message links get
the list feeds only. Providers are fakes; no network."""

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from intelhelp import Fake
from mailhelp import PHISH_LINK, eml, in_process, in_process_inspect
from sqlalchemy import create_engine, func, select

from core.api import app as app_module
from core.api.app import create_app
from core.config import Settings
from core.contracts import ProviderStatus, VerdictState
from core.db import models as db
from core.email import engine as email_engine
from core.intel.base import Answer, ProviderError, Sends
from core.intel.orchestrator import Intel

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
LISTED = Answer(
    VerdictState.MALICIOUS, "fake list, 1 entries", "this URL is on the list",
    {"listed": "url", "feed": "phishtank"},
)  # fmt: skip
CLEAN = "https://www.example.com/page"


def client(intel: Intel | None, monkeypatch: pytest.MonkeyPatch, **over: Any) -> TestClient:
    monkeypatch.setattr(app_module, "build_intel", lambda _settings: intel)
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def post(c: TestClient, url: str) -> Any:
    return c.post("/v1/urls/analyze", json={"url": url}, headers=AUTH)


def test_without_providers_the_response_is_the_local_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = post(client(None, monkeypatch), CLEAN).json()
    assert body["verdict"]["provider_results"] == [] and body["intel_skipped"] == []
    assert body["verdict"]["engine_version"] == "1.0.0"


def test_a_provider_answer_appears_in_the_verdict_with_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = Fake("phishtank", LISTED)
    body = post(client(Intel([fake]), monkeypatch), CLEAN).json()
    v = body["verdict"]
    assert v["state"] == "SUSPICIOUS" and v["recommended_response"] == "WARN"
    (r,) = v["provider_results"]
    assert (r["provider"], r["status"], r["state"]) == ("phishtank", "OK", "MALICIOUS")
    assert r["provenance"] == "fake list, 1 entries" and r["queried_at"] and r["latency_ms"] >= 0
    assert v["engine_version"].endswith("+intel") and "Providers: 1 of 1" in v["explanation"]
    assert [s["rule_id"] for s in v["signals"]] == ["intel.phishtank.url"]


@pytest.mark.parametrize(
    "how",
    [ProviderError("http 500"), RuntimeError("boom"), TimeoutError(), {"state": "MALICIOUS"}],
)
def test_a_failing_provider_still_returns_the_local_verdict(
    monkeypatch: pytest.MonkeyPatch, how: Any
) -> None:
    broken = Fake("phishtank", how, timeout=0.05)
    local = post(client(None, monkeypatch), "https://paypal.com@secure-check.test/login.php").json()
    mixed = post(
        client(Intel([broken]), monkeypatch), "https://paypal.com@secure-check.test/login.php"
    ).json()
    assert mixed["verdict"]["state"] == local["verdict"]["state"]
    assert mixed["verdict"]["risk_score"] == local["verdict"]["risk_score"]
    (r,) = mixed["verdict"]["provider_results"]
    assert r["status"] != "OK" and r["state"] is None


def test_a_provider_that_cannot_be_asked_is_listed_as_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside = Fake("rdap", sends=Sends.HOST)
    body = post(client(Intel([outside]), monkeypatch), "https://paypal-login.test/").json()
    assert outside.calls == 0
    assert body["intel_skipped"] == [
        {"provider": "rdap", "reason": "not a public name, or an established site: not sent out"}
    ]


def test_the_request_cannot_choose_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = Fake("phishtank", LISTED)
    c = client(Intel([fake]), monkeypatch)
    for extra in ({"providers": []}, {"intel": False}, {"fetch": True}):
        r = c.post("/v1/urls/analyze", json={"url": CLEAN, **extra}, headers=AUTH)
        assert r.status_code == 422
    assert fake.calls == 0


def test_a_provider_cannot_hold_the_response_past_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import time

    async def hang(_q: Any) -> Answer:
        await asyncio.sleep(5)
        return LISTED

    fake = Fake("slow", hang, timeout=10.0)
    t0 = time.perf_counter()
    body = post(client(Intel([fake], deadline=0.1), monkeypatch), CLEAN).json()
    assert time.perf_counter() - t0 < 2
    assert body["verdict"]["provider_results"][0]["status"] == "TIMEOUT"
    assert body["verdict"]["state"] == "UNKNOWN"


# ---- health --------------------------------------------------------------------------------------


def test_health_lists_providers_and_feed_age_and_needs_the_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c = client(
        Intel([Fake("phishtank")]), monkeypatch, intel_providers="phishtank", data_dir=tmp_path
    )
    assert c.get("/v1/intel/health").status_code == 401
    body = c.get("/v1/intel/health", headers=AUTH).json()
    assert body["providers"] == [
        {"provider": "phishtank", "sends": "nothing", "breaker": "closed", "usable": True}
    ]
    assert body["feeds"] == [
        {"feed": "phishtank", "downloaded": False, "entries": 0, "age_hours": None, "stale": True}
    ]
    assert "key" not in str(body).lower()


def test_health_with_no_providers_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    body = client(None, monkeypatch).get("/v1/intel/health", headers=AUTH).json()
    assert body == {"providers": [], "feeds": []}


def test_an_unknown_provider_name_stops_start_up() -> None:
    with pytest.raises(ValueError, match="nonesuch"):
        create_app(Settings(_env_file=None, api_token=TOKEN, intel_providers="phishtank,nonesuch"))


# ---- persistence ---------------------------------------------------------------------------------


def sqlite_url(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'lynceus.db'}"
    db.Base.metadata.create_all(create_engine(url))
    return url


def test_provider_results_and_the_enable_audit_record_are_stored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    url = sqlite_url(tmp_path)
    intel = Intel([Fake("phishtank", LISTED), Fake("openphish", ProviderError("http 500"))])
    c = client(intel, monkeypatch, database_url=url)
    body = post(c, CLEAN).json()
    assert body["persisted"] is True
    with create_engine(url).connect() as conn:
        rows = conn.execute(select(db.ProviderResult).order_by(db.ProviderResult.provider)).all()
        audits = conn.execute(select(db.AuditLog)).all()
        verdicts = conn.scalar(select(func.count()).select_from(db.Verdict))
    assert [(r.provider, r.status, r.state) for r in rows] == [
        ("openphish", ProviderStatus.ERROR.value, None),
        ("phishtank", ProviderStatus.OK.value, "MALICIOUS"),
    ]
    assert all(r.provenance for r in rows) and verdicts == 1
    assert {a.action for a in audits} == {"intel.enable"}
    assert {a.detail["provider"] for a in audits} == {"phishtank", "openphish"}


# ---- message links -------------------------------------------------------------------------------


@pytest.fixture
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(email_engine, "run_sandbox", in_process)
    monkeypatch.setattr(email_engine, "run_inspect", in_process_inspect)


def test_message_links_get_the_list_feeds_and_the_message_score_rises(
    monkeypatch: pytest.MonkeyPatch, fake_sandbox: None
) -> None:
    raw = eml(text="See https://www.example.com/offer for details")
    plain = client(None, monkeypatch)
    feeds = Fake("phishtank", LISTED)
    mixed = client(Intel([feeds]), monkeypatch)
    headers = AUTH | {"Content-Type": "message/rfc822"}
    before = plain.post("/v1/emails/analyze", content=raw, headers=headers).json()
    after = mixed.post("/v1/emails/analyze", content=raw, headers=headers).json()
    assert before["verdict"]["state"] == "UNKNOWN" and feeds.calls == 1
    assert after["verdict"]["state"] == "SUSPICIOUS"
    ids = {s["rule_id"] for s in after["verdict"]["signals"]}
    assert "intel.phishtank.url" in ids and [link["rules"] for link in after["links"]] == [
        ["intel.phishtank.url"]
    ]


def test_message_links_never_reach_an_outside_provider_by_default(
    monkeypatch: pytest.MonkeyPatch, fake_sandbox: None
) -> None:
    outside = Fake("rdap", sends=Sends.HOST)
    c = client(Intel([outside]), monkeypatch)
    raw = eml(html=PHISH_LINK, text=None)
    r = c.post("/v1/emails/analyze", content=raw, headers=AUTH | {"Content-Type": "message/rfc822"})
    assert r.status_code == 200 and outside.calls == 0
