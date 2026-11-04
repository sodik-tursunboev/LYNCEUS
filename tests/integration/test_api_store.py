"""The API with storage attached. Storage trouble must never cost the caller the verdict."""

from pathlib import Path

from dbhelp import upgrade
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select

from core.api.app import create_app
from core.config import Settings
from core.db import models as db

TOKEN = "test-token-for-unit-tests"  # pragma: allowlist secret
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def client(url: str) -> TestClient:
    settings = Settings(_env_file=None, api_token=TOKEN, database_url=url)  # type: ignore[arg-type]
    return TestClient(create_app(settings), base_url="http://127.0.0.1")


def test_an_analysis_is_persisted(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'a.db'}"
    engine = create_engine(url)
    upgrade(engine)
    r = client(url).post(
        "/v1/urls/analyze", json={"url": "https://paypal-login.test/"}, headers=AUTH
    )
    assert r.status_code == 200 and r.json()["persisted"] is True
    with engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(db.Verdict)) == 1
        source = c.scalar(select(db.Event.source))
    assert source == "API"
    engine.dispose()


def test_a_storage_failure_still_returns_the_verdict(tmp_path: Path) -> None:
    missing = tmp_path / "no" / "such" / "dir" / "a.db"
    r = client(f"sqlite:///{missing}").post(
        "/v1/urls/analyze", json={"url": "https://paypal-login.test/"}, headers=AUTH
    )
    assert r.status_code == 200
    assert r.json()["persisted"] is False and r.json()["verdict"]["state"] == "SUSPICIOUS"
