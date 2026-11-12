"""POST /v1/urls/detonate (D1): off by default, one verdict over URL and page, the screenshot only
through the sandbox re-encoder. The container is a fake here; tests/detonator runs the real one."""

from typing import Any

import pytest
from fastapi.testclient import TestClient

from core.api import app as api
from core.config import Settings
from core.detection.engine import UrlAnalysis
from core.detonate.judge import judge
from core.detonate.models import PageReport

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PATH = "/v1/urls/detonate"
KIT = PageReport.model_validate({
    "status": "ok", "final_url": "https://secure-check.example/o365/", "http_status": 200,
    "chain": ["https://short.example/x", "https://secure-check.example/o365/"],
    "title": "Sign in to your Microsoft account",
    "forms": [{"action": "http://203.0.113.9/next.php", "method": "post",
               "fields": [{"type": "email", "hint": "email"}, {"type": "password", "hint": "pw"}]}],
    "script_refs": ["api.telegram.org/bot0"], "markers": ["devtools_check"],
    "screenshot": "c2NyZWVu", "elapsed_ms": 1234,
})  # fmt: skip


def client(monkeypatch: pytest.MonkeyPatch, **over: Any) -> TestClient:
    def fake_detonate(raw: str, start: UrlAnalysis | None = None) -> tuple[UrlAnalysis, PageReport]:
        assert start is not None  # the URL verdict comes first, intelligence included
        return judge(start, KIT), KIT

    monkeypatch.setattr(api, "detonate_url", fake_detonate)
    monkeypatch.setattr(api, "safe_screenshot", lambda b64: "RE-ENCODED" if b64 else None)
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(api.create_app(settings), base_url="http://127.0.0.1")


def test_detonation_is_off_unless_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    r = client(monkeypatch).post(PATH, json={"url": "https://x.example/"}, headers=AUTH)
    assert r.status_code == 403


def test_it_needs_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    r = client(monkeypatch, detonation=True).post(PATH, json={"url": "https://x.example/"})
    assert r.status_code == 401


def test_one_verdict_over_url_and_page(monkeypatch: pytest.MonkeyPatch) -> None:
    r = client(monkeypatch, detonation=True).post(
        PATH, json={"url": "https://short.example/x"}, headers=AUTH
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["state"] == "MALICIOUS"
    assert body["verdict"]["engine_version"].endswith("+page")
    page = body["page"]
    assert page["chain_hosts"] == ["short.example", "secure-check.example"]
    assert page["password_fields"] == 1 and page["forms"] == 1
    assert page["screenshot_jpeg"] == "RE-ENCODED"  # never the container's own bytes
    assert body["anatomy"]["registered_domain"] == "short.example"


def test_it_has_its_own_small_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    c = client(monkeypatch, detonation=True, detonation_per_minute=2)
    codes = [c.post(PATH, json={"url": "https://a.example/"}, headers=AUTH).status_code
             for _ in range(3)]  # fmt: skip
    assert codes == [200, 200, 429]
