"""DA1 P3 through the API: a risky link the browser checks is opened in the background, and the
browser's next check of it gets the deeper verdict. The container is a fake (tests/detonator runs
the real one); everything else is the real core."""

import time
from pathlib import Path
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
BROWSER = {**AUTH, "X-Lynceus-Source": "BROWSER"}
RISKY = "https://account-review.test/login"  # one weak sign: worth a look, not a verdict
KIT = PageReport.model_validate({
    "status": "ok", "final_url": RISKY, "http_status": 200,
    "title": "Sign in to your Microsoft account",
    "forms": [{"action": "http://203.0.113.9/next.php", "method": "post",
               "fields": [{"type": "email", "hint": "email"}, {"type": "password", "hint": "pw"}]}],
    "script_refs": ["api.telegram.org/bot0"],
})  # fmt: skip


def client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **over: Any
) -> tuple[TestClient, list[bool]]:
    opened: list[bool] = []

    def fake_detonate(
        raw: str, start: UrlAnalysis | None = None, *, auto: bool = False
    ) -> tuple[UrlAnalysis, PageReport]:
        assert start is not None
        opened.append(auto)
        return judge(start, KIT, auto=auto), KIT

    monkeypatch.setattr(api, "detonate_url", fake_detonate)
    settings = Settings(_env_file=None, api_token=TOKEN, data_dir=tmp_path, **over)
    return TestClient(api.create_app(settings), base_url="http://127.0.0.1"), opened


def check(c: TestClient, headers: dict[str, str], url: str = RISKY) -> dict[str, Any]:
    r = c.post("/v1/urls/analyze", json={"url": url}, headers=headers)
    assert r.status_code == 200
    return r.json()


def until_graver(c: TestClient, seconds: float = 10.0) -> dict[str, Any]:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        body = check(c, BROWSER)
        if body["verdict"]["state"] == "MALICIOUS":
            return body
        time.sleep(0.05)
    raise AssertionError("the deeper verdict never reached the browser")


def test_a_risky_browser_link_is_opened_and_the_next_check_gets_the_page_verdict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, opened = client(monkeypatch, tmp_path, detonation=True, auto_detonation="browser")
    first = check(c, BROWSER)
    assert first["verdict"]["state"] in ("SUSPICIOUS", "UNKNOWN")  # the address alone, at once
    later = until_graver(c)
    assert opened == [True]  # opened once, and marked as automatic
    assert "automatically" in later["verdict"]["explanation"]
    assert any(s["rule_id"].startswith("page.") for s in later["verdict"]["signals"])
    audit = (
        (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        if (tmp_path / "audit.jsonl").exists()
        else ""
    )
    assert "account-review" not in audit and "jane" not in audit  # no address in any record


def test_a_check_from_the_console_or_another_caller_opens_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, opened = client(monkeypatch, tmp_path, detonation=True, auto_detonation="browser")
    check(c, AUTH)  # no browser header: a plain API call (the console has its own button)
    time.sleep(0.3)
    assert opened == []


def test_nothing_is_opened_while_detonation_itself_is_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, opened = client(monkeypatch, tmp_path, auto_detonation="browser,mail")
    check(c, BROWSER)
    time.sleep(0.3)
    assert opened == []


def test_mail_alone_does_not_open_browser_links(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, opened = client(monkeypatch, tmp_path, detonation=True, auto_detonation="mail")
    check(c, BROWSER)
    time.sleep(0.3)
    assert opened == []


def test_a_wrong_setting_stops_the_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="browser and mail"):
        client(monkeypatch, tmp_path, detonation=True, auto_detonation="browser,phone")
