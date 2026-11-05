"""The console is served from the core with strict headers, and only if it has been built (M6)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app
from core.api.console import CSP
from core.config import Settings

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret


def app_with(tmp_path: Path, built: bool = True) -> TestClient:
    site = tmp_path / "dist"
    if built:
        site.mkdir()
        (site / "index.html").write_text("<!doctype html><title>c</title>", encoding="utf-8")
        (site / "console.js").write_text("console.log(1)", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    settings = Settings(_env_file=None, api_token=TOKEN, console_dir=site, data_dir=tmp_path / "d")
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def test_the_console_page_and_script_are_served_with_the_strict_headers(tmp_path: Path) -> None:
    c = app_with(tmp_path)
    for path in ("/console/", "/console/console.js", "/console/nope.js"):
        r = c.get(path)
        assert r.status_code in (200, 404)
        assert r.headers["content-security-policy"] == CSP
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["referrer-policy"] == "no-referrer"
    assert c.get("/console/").status_code == 200 and "<title>c</title>" in c.get("/console/").text
    assert c.get("/console/console.js").status_code == 200


def test_the_policy_allows_no_inline_script_no_other_origin_and_no_framing() -> None:
    assert "default-src 'self'" in CSP and "script-src 'self'" in CSP and "unsafe-inline" not in CSP
    assert (
        "frame-ancestors 'none'" in CSP
        and "connect-src 'self'" in CSP
        and "object-src 'none'" in CSP
    )
    assert "http:" not in CSP and "https:" not in CSP and "*" not in CSP


@pytest.mark.parametrize(
    "path",
    [
        "/console/../secret.txt",
        "/console/%2e%2e/secret.txt",
        "/console/..%2fsecret.txt",
        "/console/%2e%2e%5csecret.txt",
    ],
)
def test_nothing_outside_the_console_folder_is_reachable(tmp_path: Path, path: str) -> None:
    r = app_with(tmp_path).get(path)
    assert "TOP SECRET" not in r.text


def test_only_reading_is_allowed_and_the_api_still_needs_its_token(tmp_path: Path) -> None:
    c = app_with(tmp_path)
    assert c.post("/console/", content=b"x").status_code in (404, 405)
    assert c.get("/v1/events").status_code == 401
    assert c.get("/v1/audit").status_code == 401


def test_without_a_built_console_there_is_no_console_route(tmp_path: Path) -> None:
    c = app_with(tmp_path, built=False)
    assert c.get("/console/").status_code == 404
    assert c.get("/health").status_code == 200


def test_another_host_name_is_refused_as_for_the_rest_of_the_api(tmp_path: Path) -> None:
    c = app_with(tmp_path)
    assert c.get("/console/", headers={"Host": "evil.test"}).status_code == 400
