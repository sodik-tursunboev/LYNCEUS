"""Database tests run on SQLite always, and on a real PostgreSQL inside a throw-away schema when
LYNCEUS_TEST_DATABASE_URL points at one (skipped otherwise). PostgreSQL is the production target."""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from dbhelp import upgrade
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import OperationalError


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.integration)])
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
        yield eng
        eng.dispose()
        return
    # the old name (MIRAGE_) still works
    url = os.environ.get("LYNCEUS_TEST_DATABASE_URL") or os.environ.get("MIRAGE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("LYNCEUS_TEST_DATABASE_URL not set")
    admin = create_engine(url)
    try:
        admin.connect().close()
    except OperationalError:
        pytest.skip("PostgreSQL not reachable")
    schema = f"t_{uuid.uuid4().hex[:12]}"
    with admin.begin() as c:
        c.execute(text(f'CREATE SCHEMA "{schema}"'))  # noqa: S608
    eng = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    yield eng
    eng.dispose()
    with admin.begin() as c:
        c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))  # noqa: S608
    admin.dispose()


@pytest.fixture
def migrated(engine: Engine) -> Engine:
    upgrade(engine)
    return engine
