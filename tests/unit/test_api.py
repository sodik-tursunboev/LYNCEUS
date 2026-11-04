import pytest
from fastapi.testclient import TestClient

from core.api.app import create_app
from core.config import Settings


def test_health() -> None:
    r = TestClient(create_app(Settings(_env_file=None))).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_settings_read_env_with_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")
    assert Settings(_env_file=None).log_level == "DEBUG"


def test_database_url_is_hidden_in_repr() -> None:
    s = Settings(_env_file=None, database_url="postgresql://u:s3cretpw@h/db")  # type: ignore[arg-type]  # pragma: allowlist secret
    assert "s3cretpw" not in repr(s) and "s3cretpw" not in str(s)
    assert s.database_url is not None
    assert "s3cretpw" in s.database_url.get_secret_value()  # pragma: allowlist secret
