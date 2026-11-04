"""Migration tests.

Every test runs on SQLite (fast schema check). The `postgres` variant runs the same tests against a
real server when MIRAGE_TEST_DATABASE_URL points at one, inside a throw-away schema; otherwise it
is skipped. PostgreSQL is the production target, so until that variant has run, "migrations apply
to an empty database" is only verified for SQLite (see docs/KNOWN_LIMITATIONS.md).
"""

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError

from core.db.models import Base

ROOT = Path(__file__).parents[2]
TABLES = {
    "events", "artifacts", "extracted_urls", "domains", "provider_results", "detections",
    "verdicts", "evidence", "evidence_payloads", "audit_logs",
}  # fmt: skip
LOOKUPS = {
    "events": ["observed_at"],
    "artifacts": ["sha256", "event_id"],
    "domains": ["name", "registered_domain"],
    "extracted_urls": ["artifact_id", "url_sha256", "domain_id"],
    "provider_results": ["artifact_id", "provider"],
    "detections": ["artifact_id", "rule_id"],
    "verdicts": ["artifact_id", "state"],
    "evidence": ["artifact_id", "sha256", "payload_id"],
    "audit_logs": ["action", "target_id", "at"],
}


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.integration)])
def engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Engine]:
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
        yield eng
        eng.dispose()
        return
    url = os.environ.get("MIRAGE_TEST_DATABASE_URL")
    if not url:
        pytest.skip("MIRAGE_TEST_DATABASE_URL not set")
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


def _cfg(conn: sa.Connection) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["connection"] = conn
    return cfg


def _upgrade(engine: Engine) -> None:
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")


def test_migrations_apply_to_an_empty_database(engine: Engine) -> None:
    assert inspect(engine).get_table_names() == []
    _upgrade(engine)
    assert set(inspect(engine).get_table_names()) == TABLES | {"alembic_version"}


def test_upgrade_is_repeatable_and_downgrade_is_clean(engine: Engine) -> None:
    _upgrade(engine)
    _upgrade(engine)  # already at head: no-op, no error
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    _upgrade(engine)  # and it comes back
    assert set(inspect(engine).get_table_names()) == TABLES | {"alembic_version"}


def test_lookup_columns_are_indexed(engine: Engine) -> None:
    _upgrade(engine)
    insp = inspect(engine)
    for table, cols in LOOKUPS.items():
        covered = [i["column_names"] for i in insp.get_indexes(table)]
        covered += [u["column_names"] for u in insp.get_unique_constraints(table)]
        for col in cols:
            assert any(c and c[0] == col for c in covered), f"{table}.{col} has no index"


def test_migration_matches_the_models(engine: Engine) -> None:
    _upgrade(engine)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []


def test_sensitive_bytes_live_only_in_evidence_payloads(engine: Engine) -> None:
    _upgrade(engine)
    insp = inspect(engine)
    for table in TABLES - {"evidence_payloads"}:
        blobs = [
            c["name"] for c in insp.get_columns(table) if isinstance(c["type"], sa.LargeBinary)
        ]
        assert not blobs, f"{table} stores binary data: {blobs}"
    assert {"ciphertext", "key_id"} <= {c["name"] for c in insp.get_columns("evidence_payloads")}
    assert "payload_id" in {c["name"] for c in insp.get_columns("evidence")}


# ---- CHECK constraints repeat the contract invariants -----------------------------------------


@pytest.fixture
def artifact_id(engine: Engine) -> uuid.UUID:
    _upgrade(engine)
    t = Base.metadata.tables
    event_id, art_id = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            sa.insert(t["events"]).values(id=event_id, source="API", observed_at=datetime.now(UTC))
        )
        conn.execute(
            sa.insert(t["artifacts"]).values(
                id=art_id, event_id=event_id, kind="URL", sha256="0" * 64, ref="https://a.test/"
            )
        )
    return art_id


def _verdict(art: uuid.UUID, **over: Any) -> dict[str, Any]:
    row = {
        "id": uuid.uuid4(), "artifact_id": art, "state": "SUSPICIOUS", "risk_score": 40,
        "confidence": "LOW", "recommended_response": "NONE", "applied_response": "NONE",
        "explanation": "t", "engine_version": "t",
    }  # fmt: skip
    return row | over


def _provider(art: uuid.UUID, **over: Any) -> dict[str, Any]:
    row = {
        "id": uuid.uuid4(), "artifact_id": art, "provider": "p", "status": "OK", "state": "BENIGN",
        "queried_at": datetime.now(UTC), "latency_ms": 1, "provenance": "x",
    }  # fmt: skip
    return row | over


@pytest.mark.parametrize(
    "bad",
    [
        {"state": "UNKNOWN", "risk_score": 0},  # a 0 would read as "safe"
        {"state": "ERROR", "risk_score": 10},
        {"state": "BENIGN", "risk_score": None},
        {"state": "MALICIOUS", "risk_score": 101},
        {"state": "BOGUS", "risk_score": 10},
        {"applied_response": "DELETE"},
    ],
)
def test_verdict_checks_reject_bad_rows(
    engine: Engine, artifact_id: uuid.UUID, bad: dict[str, Any]
) -> None:
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(
            sa.insert(Base.metadata.tables["verdicts"]).values(_verdict(artifact_id, **bad))
        )


@pytest.mark.parametrize(
    "good", [{}, {"state": "UNKNOWN", "risk_score": None}, {"state": "ERROR", "risk_score": None}]
)
def test_verdict_checks_accept_valid_rows(
    engine: Engine, artifact_id: uuid.UUID, good: dict[str, Any]
) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.insert(Base.metadata.tables["verdicts"]).values(_verdict(artifact_id, **good))
        )


@pytest.mark.parametrize(
    "bad",
    [
        {"status": "OK", "state": None},  # an answer without an opinion
        {"status": "TIMEOUT", "state": "BENIGN"},  # a failure must not look like an opinion
        {"status": "ERROR", "state": "UNKNOWN"},
        {"status": "OK", "state": "ERROR"},
    ],
)
def test_provider_checks_reject_bad_rows(
    engine: Engine, artifact_id: uuid.UUID, bad: dict[str, Any]
) -> None:
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(
            sa.insert(Base.metadata.tables["provider_results"]).values(
                _provider(artifact_id, **bad)
            )
        )


@pytest.mark.parametrize(
    "good", [{}, {"status": "TIMEOUT", "state": None}, {"status": "RATE_LIMITED", "state": None}]
)
def test_provider_checks_accept_valid_rows(
    engine: Engine, artifact_id: uuid.UUID, good: dict[str, Any]
) -> None:
    with engine.begin() as conn:
        conn.execute(
            sa.insert(Base.metadata.tables["provider_results"]).values(
                _provider(artifact_id, **good)
            )
        )
