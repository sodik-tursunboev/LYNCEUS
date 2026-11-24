"""DA5 1b through the API: while a risky browser link is being opened in the sandbox, the check's
answer says when to ask again, and that second check gets the page's verdict. The container is a
fake held shut by a gate, so "running" and "landed" are exact moments, not races."""

import threading
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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    fail: bool = False,
    **over: Any,
) -> tuple[TestClient, threading.Event, list[str]]:
    gate, opened = threading.Event(), []

    def fake_detonate(
        raw: str, start: UrlAnalysis | None = None, *, auto: bool = False
    ) -> tuple[UrlAnalysis, PageReport]:
        assert start is not None
        gate.wait(10)  # the sandbox is "busy" until the test opens the gate
        opened.append(raw)
        if fail:
            raise RuntimeError("the container failed")
        return judge(start, KIT, auto=auto), KIT

    monkeypatch.setattr(api, "detonate_url", fake_detonate)
    settings = Settings(_env_file=None, api_token=TOKEN, data_dir=tmp_path, **over)
    app = api.create_app(settings)
    return TestClient(app, base_url="http://127.0.0.1"), gate, opened


def check(c: TestClient, headers: dict[str, str] = BROWSER, url: str = RISKY) -> dict[str, Any]:
    r = c.post("/v1/urls/analyze", json={"url": url}, headers=headers)
    assert r.status_code == 200
    body: dict[str, Any] = r.json()
    return body


def until(c: TestClient, done: Any, seconds: float = 10.0) -> dict[str, Any]:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        body = check(c)
        if done(body):
            return body
        time.sleep(0.05)
    raise AssertionError("the check never reached the expected answer")


def test_a_check_says_when_a_deeper_look_is_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, gate, _ = client(monkeypatch, tmp_path, detonation=True, auto_detonation="browser")
    try:
        first = check(c)
        assert first["verdict"]["state"] in ("SUSPICIOUS", "UNKNOWN")  # the address alone, at once
        assert first["deeper"]["state"] == "running"
        assert 2 <= first["deeper"]["retry_after_s"] <= 12
        again = check(c)  # a second tab, same address, while the sandbox is still busy
        assert again["deeper"]["state"] == "running"
        assert again["deeper"]["retry_after_s"] <= first["deeper"]["retry_after_s"]
        assert again["verdict"]["state"] == first["verdict"]["state"]  # nothing is invented
    finally:
        gate.set()


def test_the_deeper_verdict_is_returned_when_it_lands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c, gate, opened = client(monkeypatch, tmp_path, detonation=True, auto_detonation="browser")
    assert check(c)["deeper"] is not None
    gate.set()
    landed = until(c, lambda b: b["verdict"]["state"] == "MALICIOUS")
    assert landed["deeper"] is None  # nothing is pending any more
    assert any(s["rule_id"].startswith("page.") for s in landed["verdict"]["signals"])
    assert opened == [RISKY]  # opened once, however often it was asked
    assert check(c)["verdict"]["state"] == "MALICIOUS"  # and it stays given back

    # an opening that fails ends the wait: no note for a verdict that will never come
    (tmp_path / "b").mkdir()
    broken, open_gate, tried = client(
        monkeypatch, tmp_path / "b", fail=True, detonation=True, auto_detonation="browser"
    )
    assert check(broken)["deeper"] is not None
    open_gate.set()
    body = until(broken, lambda b: b["deeper"] is None)
    assert body["verdict"]["state"] in ("SUSPICIOUS", "UNKNOWN") and tried == [RISKY]


def test_no_deeper_look_for_a_site_that_is_not_opened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    browser = {"auto_detonation": "browser"}
    cases: list[tuple[str, dict[str, str], dict[str, Any]]] = [
        ("https://www.microsoft.com/", BROWSER, browser),  # a brand's own site
        ("https://example.test/blog/notes", BROWSER, browser),  # no sign at all
        (RISKY, AUTH, browser),  # not from the browser (the console has its own button)
        (RISKY, BROWSER, {"auto_detonation": "mail"}),  # browser links were not chosen
        (RISKY, BROWSER, {"auto_detonation": ""}),  # automatic opening is off
        (RISKY, BROWSER, {**browser, "detonation": False}),  # detonation itself is off
    ]
    for i, (url, headers, over) in enumerate(cases):
        (tmp_path / str(i)).mkdir()
        c, gate, opened = client(monkeypatch, tmp_path / str(i), **{"detonation": True, **over})
        try:
            assert check(c, headers, url)["deeper"] is None, (url, over)
            time.sleep(0.1)
            assert opened == [], (url, over)
        finally:
            gate.set()
