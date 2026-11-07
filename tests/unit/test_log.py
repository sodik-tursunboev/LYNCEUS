import io
import json
import logging
from collections.abc import Iterator

import pytest

from core.log import LynceusHandler, RedactingJsonFormatter, configure, redact_value

# Obviously fake values. Each carries the secret-scanner pragma on its own line, and URLs are
# assembled from them so no URL with embedded credentials sits in the source.
PW = "hunter2"  # pragma: allowlist secret
TOKEN = "zzz999"  # pragma: allowlist secret
BEARER = "abcdef1234567890"  # pragma: allowlist secret
DB_PW = "s3cretpw"  # pragma: allowlist secret
USER_PW = "p4ss"  # pragma: allowlist secret
QS_TOKEN = "SECRET123"  # pragma: allowlist secret

Emit = tuple[logging.Logger, io.StringIO]


@pytest.fixture
def emit() -> Iterator[Emit]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(RedactingJsonFormatter())
    log = logging.getLogger("test.redaction")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    log.addHandler(handler)
    yield log, buf
    log.removeHandler(handler)


def last(buf: io.StringIO) -> dict[str, object]:
    rec: dict[str, object] = json.loads(buf.getvalue().strip().splitlines()[-1])
    return rec


def test_url_is_logged_as_host_and_hash_only(emit: Emit) -> None:
    log, buf = emit
    userinfo = f"bob:{PW}"
    url = f"https://{userinfo}@login.examplebank.test/a/b?email=jane%40x.test&token={TOKEN}"
    log.info("fetching %s now", url)
    raw = buf.getvalue()
    msg = str(last(buf)["msg"])
    assert "login.examplebank.test" in msg and "sha=" in msg
    for leaked in (PW, "bob", "/a/b", "jane", TOKEN, "email="):
        assert leaked not in raw


def test_sensitive_extra_keys_are_redacted(emit: Emit) -> None:
    log, buf = emit
    log.info("login", extra={"password": PW, "api_key": TOKEN, "attempt": 3})
    rec = last(buf)
    assert rec["password"] == rec["api_key"] == "[REDACTED]"
    assert rec["attempt"] == 3  # harmless fields survive


def test_nested_structures_and_headers(emit: Emit) -> None:
    log, buf = emit
    headers = {"Authorization": f"Bearer {BEARER}", "Accept": "json"}
    log.info("req", extra={"headers": headers})
    raw = buf.getvalue()
    assert BEARER not in raw
    assert json.loads(raw)["headers"]["Accept"] == "json"


def test_free_text_secrets(emit: Emit) -> None:
    log, buf = emit
    log.warning("auth failed: Authorization: Bearer %s token=%s password: %s", BEARER, TOKEN, PW)
    raw = buf.getvalue()
    for leaked in (BEARER, TOKEN, PW):
        assert leaked not in raw


def test_secrets_named_by_what_this_project_handles_are_redacted(emit: Emit) -> None:
    log, buf = emit
    lines = [
        f"refresh_token={TOKEN}",
        f"access_token: {TOKEN}",
        f"client_secret={TOKEN}",
        f"id_token={TOKEN}",
        f"LYNCEUS_API_TOKEN={TOKEN}",
        f"POSTGRES_PASSWORD={TOKEN}",
        f'{{"refresh_token": "{TOKEN}", "scope": "Mail.Read"}}',
        f"x-api-key: {TOKEN}",
    ]
    for line in lines:
        log.warning("failed with %s", line)
        assert TOKEN not in buf.getvalue(), line
    log.info("passed 3 tests, status code: 404, scope=Mail.Read")
    assert "passed 3 tests, status code: 404, scope=Mail.Read" in str(last(buf)["msg"])


def test_database_url_never_logged(emit: Emit) -> None:
    log, buf = emit
    dsn = f"postgresql+psycopg://mirage:{DB_PW}@localhost:5432/mirage"  # pragma: allowlist secret
    log.info("db", extra={"conn": dsn})
    assert DB_PW not in buf.getvalue()


def test_exception_tracebacks_are_redacted(emit: Emit) -> None:
    log, buf = emit
    url = f"https://u:{USER_PW}@evil.invalid/x?token={QS_TOKEN}"  # pragma: allowlist secret
    try:
        raise ValueError(f"fetch failed {url}")
    except ValueError:
        log.exception("boom")
    raw = buf.getvalue()
    assert QS_TOKEN not in raw and USER_PW not in raw
    assert "evil.invalid" in raw


def test_every_line_is_valid_json(emit: Emit) -> None:
    log, buf = emit
    log.info("a")
    log.error("b %s", "c")
    for ln in buf.getvalue().splitlines():
        assert {"ts", "level", "logger", "msg"} <= json.loads(ln).keys()


def test_redact_value_keeps_plain_types() -> None:
    value = {"n": 1, "ok": True, "x": None, "t": [1, "a"]}
    assert redact_value(value) == value


def test_configure_is_idempotent() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        configure("INFO", io.StringIO())
        configure("DEBUG", io.StringIO())
        assert sum(isinstance(h, LynceusHandler) for h in root.handlers) == 1
    finally:
        root.handlers = before
