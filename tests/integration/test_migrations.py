"""Migration tests. See conftest.py for how each runs on SQLite and on real PostgreSQL."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from dbhelp import alembic_config, upgrade
from sqlalchemy import Engine, inspect
from sqlalchemy.exc import IntegrityError

from core.db.models import Base

TABLES = {
    "events", "artifacts", "extracted_urls", "domains", "provider_results", "detections",
    "verdicts", "evidence", "evidence_payloads", "detection_evidence", "audit_logs",
    "actions", "allowlist",
}  # fmt: skip
LOOKUPS = {
    "events": ["observed_at"],
    "artifacts": ["sha256", "event_id", "host"],
    "domains": ["name", "registered_domain"],
    "extracted_urls": ["artifact_id", "url_sha256", "domain_id"],
    "provider_results": ["artifact_id", "provider"],
    "detections": ["artifact_id", "rule_id"],
    "verdicts": ["artifact_id", "state"],
    "evidence": ["artifact_id", "sha256", "payload_id"],
    "detection_evidence": ["evidence_id"],
    "audit_logs": ["action", "target_id", "at"],
    "actions": ["sha256", "state", "verdict_id", "file_ref"],
    "allowlist": ["sha256"],
}


def test_migrations_apply_to_an_empty_database(engine: Engine) -> None:
    assert inspect(engine).get_table_names() == []
    upgrade(engine)
    assert set(inspect(engine).get_table_names()) == TABLES | {"alembic_version"}


def test_upgrade_is_repeatable_and_downgrade_is_clean(engine: Engine) -> None:
    upgrade(engine)
    upgrade(engine)  # already at head: no-op, no error
    with engine.begin() as conn:
        command.downgrade(alembic_config(conn), "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    upgrade(engine)  # and it comes back
    assert set(inspect(engine).get_table_names()) == TABLES | {"alembic_version"}


def test_lookup_columns_are_indexed(engine: Engine) -> None:
    upgrade(engine)
    insp = inspect(engine)
    for table, cols in LOOKUPS.items():
        covered = [i["column_names"] for i in insp.get_indexes(table)]
        covered += [u["column_names"] for u in insp.get_unique_constraints(table)]
        for col in cols:
            assert any(c and c[0] == col for c in covered), f"{table}.{col} has no index"


def test_migration_matches_the_models(engine: Engine) -> None:
    upgrade(engine)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []


def test_sensitive_bytes_live_only_in_evidence_payloads(engine: Engine) -> None:
    upgrade(engine)
    insp = inspect(engine)
    for table in TABLES - {"evidence_payloads"}:
        blobs = [
            c["name"] for c in insp.get_columns(table) if isinstance(c["type"], sa.LargeBinary)
        ]
        assert not blobs, f"{table} stores binary data: {blobs}"
    assert {"ciphertext", "key_id"} <= {c["name"] for c in insp.get_columns("evidence_payloads")}
    assert "payload_id" in {c["name"] for c in insp.get_columns("evidence")}


def test_0003_keeps_file_actions_enforces_the_mail_rules_and_downgrades_cleanly(
    engine: Engine,
) -> None:
    t = Base.metadata.tables
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "0002")
    assert {"provider", "mail_ref"}.isdisjoint(
        c["name"] for c in inspect(engine).get_columns("actions")
    )
    event_id, art_id, verdict_id, file_action = (uuid.uuid4() for _ in range(4))
    with engine.begin() as conn:
        conn.execute(
            sa.insert(t["events"]).values(id=event_id, source="API", observed_at=datetime.now(UTC))
        )
        conn.execute(
            sa.insert(t["artifacts"]).values(
                id=art_id, event_id=event_id, kind="URL", sha256="0" * 64, ref="https://a.test/"
            )
        )
        conn.execute(sa.insert(t["verdicts"]).values(_verdict(art_id, id=verdict_id)))
        conn.execute(  # a file action as migration 0002 knew it (only the columns it had)
            sa.insert(t["actions"]).values(
                id=file_action,
                verdict_id=verdict_id,
                kind="FILE_QUARANTINE",
                state="PENDING",
                file_ref="a" * 32,
                sha256="b" * 64,
            )  # fmt: skip
        )
    upgrade(engine)
    names = {c["name"] for c in inspect(engine).get_columns("actions")}
    assert {"provider", "mail_ref"} <= names
    with engine.connect() as conn:
        kept = conn.execute(sa.text("SELECT provider, mail_ref FROM actions")).all()
    assert [tuple(r) for r in kept] == [(None, None)]  # the old row is untouched

    def insert(**over: Any) -> None:
        row = {
            "id": uuid.uuid4(), "verdict_id": verdict_id, "state": "PENDING",
            "file_ref": uuid.uuid4().hex, "sha256": "c" * 64,
        } | over  # fmt: skip
        with engine.begin() as conn:
            conn.execute(sa.insert(t["actions"]).values(row))

    insert(kind="MAIL_QUARANTINE", provider="gmail", mail_ref="MSG1")
    insert(kind="MAIL_QUARANTINE", provider="outlook", mail_ref=None)  # cleared after a restore
    for bad in (
        {"kind": "MAIL_QUARANTINE"},  # no provider: a NULL must not slip through a CHECK
        {"kind": "MAIL_QUARANTINE", "provider": "yahoo", "mail_ref": "MSG2"},
        {"kind": "FILE_QUARANTINE", "provider": "gmail"},
        {"kind": "FILE_QUARANTINE", "mail_ref": "MSG3"},
        {"kind": "DELETE_EMAIL", "provider": "gmail"},
    ):
        with pytest.raises(IntegrityError):
            insert(**bad)

    with engine.begin() as conn:
        command.downgrade(alembic_config(conn), "0002")
    assert {"provider", "mail_ref"}.isdisjoint(
        c["name"] for c in inspect(engine).get_columns("actions")
    )
    with engine.connect() as conn:
        left = conn.execute(sa.text("SELECT kind FROM actions")).scalars().all()
    assert left == ["FILE_QUARANTINE"]  # mail actions cannot exist before 0003: removed
    upgrade(engine)  # and it comes forward again


# ---- CHECK constraints repeat the contract invariants -----------------------------------------


@pytest.fixture
def artifact_id(engine: Engine) -> uuid.UUID:
    upgrade(engine)
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
        "explanation": "t", "engine_version": "t", "ruleset_version": "t",
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
