import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app
from core.config import Settings
from core.contracts import Evidence, Verdict
from core.detection import engine
from core.urls.parse import MAX_URL_LEN

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}
DOCS = Path(__file__).parents[2] / "docs"
PATH = "/v1/urls/analyze"


def client(**over: Any) -> TestClient:
    settings = Settings(_env_file=None, api_token=TOKEN, **over)
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def post(c: TestClient, url: object) -> Any:
    return c.post(PATH, json={"url": url}, headers=AUTH)


def test_health_is_open_and_says_nothing_else() -> None:
    r = client().get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_full_verdict_comes_back() -> None:
    r = post(client(), "https://paypal.com@secure-check.test/login.php")
    assert r.status_code == 200
    body = r.json()
    v = body["verdict"]
    assert v["state"] in ("SUSPICIOUS", "MALICIOUS") and isinstance(v["risk_score"], int)
    assert v["confidence"] and v["recommended_response"] in ("WARN", "BLOCK")
    assert v["applied_response"] == "NONE"
    assert body["normalized_url"] == "https://paypal.com@secure-check.test/login.php"
    assert body["persisted"] is False and body["reason"] is None
    assert v["engine_version"] and v["ruleset_version"]
    for s in v["signals"]:
        assert s["rule_id"] and s["attack"] and s["evidence_ids"]
    assert {e["id"] for e in body["evidence"]} == set(v["evidence_ids"])


def test_no_signals_is_unknown_over_the_api() -> None:
    v = post(client(), "https://example.test/page").json()["verdict"]
    assert (v["state"], v["risk_score"]) == ("UNKNOWN", None)


def test_refanged_input_is_flagged_in_evidence() -> None:
    body = post(client(), "hxxps://paypal-login[.]test/").json()
    assert "REFANGED" in body["flags"]
    assert "input_note" in {e["kind"] for e in body["evidence"]}


# ---- failures are verdicts, malformed requests are not ----------------------------------------


def test_oversize_url_is_unknown_with_a_reason_not_422() -> None:
    r = post(client(), "https://example.test/" + "a" * MAX_URL_LEN)
    assert r.status_code == 200
    body = r.json()
    assert (body["verdict"]["state"], body["reason"]) == ("UNKNOWN", "too_long")
    assert body["normalized_url"] is None


def test_unparseable_url_is_unknown_with_a_reason() -> None:
    body = post(client(), "http://ex ample.test/").json()
    assert (body["verdict"]["state"], body["reason"]) == ("UNKNOWN", "unparseable")


def test_internal_failure_is_an_error_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "_rules", boom)
    r = post(client(), "https://example.test/")
    assert r.status_code == 200
    assert (r.json()["verdict"]["state"], r.json()["reason"]) == ("ERROR", "error")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json": {}},
        {"json": {"url": 5}},
        {"json": {"url": None}},
        {"json": {"url": "https://example.test/", "extra": 1}},
        {"content": b"{not json", "headers": {"Content-Type": "application/json"}},
        {"content": b"url=https://example.test/"},
    ],
)
def test_malformed_requests_are_422(kwargs: dict[str, Any]) -> None:
    headers = AUTH | kwargs.pop("headers", {})
    assert client().post(PATH, headers=headers, **kwargs).status_code == 422


def test_url_is_never_taken_from_the_query_string() -> None:
    r = client().get(PATH, params={"url": "https://example.test/"}, headers=AUTH)
    assert r.status_code == 405


def test_body_over_the_cap_is_413_with_a_declared_length() -> None:
    r = post(client(max_body_bytes=100), "https://example.test/" + "a" * 200)
    assert r.status_code == 413


def test_body_over_the_cap_is_413_when_chunked() -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"url": "'
        yield b"a" * 200
        yield b'"}'

    headers = AUTH | {"Content-Type": "application/json"}
    r = client(max_body_bytes=100).post(PATH, content=chunks(), headers=headers)
    assert r.status_code == 413


# ---- access control ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic abc"}, {"Authorization": ""}],
)
def test_bad_or_missing_token_is_401(headers: dict[str, str]) -> None:
    r = client().post(PATH, json={"url": "https://example.test/"}, headers=headers)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_non_ascii_token_is_refused_not_a_crash() -> None:
    headers = {"Authorization": "Bearer \u00fc".encode("latin-1")}
    r = client().post(PATH, json={"url": "x"}, headers=headers)  # type: ignore[arg-type]
    assert r.status_code == 401


def test_endpoint_refuses_to_serve_without_a_configured_token() -> None:
    c = TestClient(create_app(Settings(_env_file=None)), base_url="http://127.0.0.1")
    assert c.post(PATH, json={"url": "x"}, headers=AUTH).status_code == 503
    assert c.get("/health").status_code == 200


def test_unknown_host_header_is_refused() -> None:
    settings = Settings(_env_file=None, api_token=TOKEN)
    r = TestClient(create_app(settings), base_url="http://evil.test").get("/health")
    assert r.status_code == 400


def test_rate_limit() -> None:
    c = client(rate_limit_per_minute=2)
    assert [post(c, "https://example.test/").status_code for _ in range(2)] == [200, 200]
    r = post(c, "https://example.test/")
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_a_failed_login_does_not_use_up_the_limit() -> None:
    c = client(rate_limit_per_minute=1)
    assert c.post(PATH, json={"url": "x"}).status_code == 401
    assert post(c, "https://example.test/").status_code == 200


def test_no_cors_headers() -> None:
    r = client().post(
        PATH,
        json={"url": "https://example.test/"},
        headers=AUTH | {"Origin": "https://evil.test"},
    )
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_are_not_served(path: str) -> None:
    assert client().get(path).status_code == 404


# ---- contracts ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "model"), [("Verdict", Verdict), ("Evidence", Evidence)])
def test_responses_match_the_exported_schemas(name: str, model: type[Any]) -> None:
    schema = json.loads((DOCS / "schemas" / f"{name}.json").read_text(encoding="utf-8"))
    body = post(client(), "https://paypal.com@secure-check.test/").json()
    items = [body["verdict"]] if name == "Verdict" else body["evidence"]
    assert items
    for item in items:
        assert set(item) <= set(schema["properties"])
        assert set(schema["required"]) <= set(item)
        model.model_validate(item)


def test_openapi_file_is_current() -> None:
    app = create_app(Settings(_env_file=None))
    committed = json.loads((DOCS / "openapi.json").read_text(encoding="utf-8"))
    assert app.openapi() == committed, "stale: run python -m core.api.app"


def test_openapi_declares_the_bearer_scheme() -> None:
    spec = create_app(Settings(_env_file=None)).openapi()
    assert PATH in spec["paths"] and "HTTPBearer" in spec["components"]["securitySchemes"]


# ---- settings ----------------------------------------------------------------------------------


def test_settings_read_env_with_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")
    assert Settings(_env_file=None).log_level == "DEBUG"


def test_secrets_are_hidden_in_repr() -> None:
    url = "postgresql://u:s3cretpw@h/db"  # pragma: allowlist secret
    s = Settings(_env_file=None, database_url=url, api_token=TOKEN)  # type: ignore[arg-type]
    assert "s3cretpw" not in repr(s) and TOKEN not in repr(s)
    assert s.database_url is not None
    assert "s3cretpw" in s.database_url.get_secret_value()  # pragma: allowlist secret
