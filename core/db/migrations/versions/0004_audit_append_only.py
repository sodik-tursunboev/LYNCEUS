"""audit log append-only in the database itself (H1 A2)

Until now `audit_logs` was append-only by convention. A trigger now refuses UPDATE, DELETE and (on
PostgreSQL) TRUNCATE, so neither a bug nor a stolen database login can quietly rewrite history.
The owner of the database can still drop the trigger; that is a schema change, not a quiet edit.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-12 18:30:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# the same statements as core/db/models.py (APPEND_ONLY), copied so this migration never changes
UP = {
    "postgresql": [
        "CREATE FUNCTION audit_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS "
        "$$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$",
        "CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()",
        "CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only()",
    ],
    "sqlite": [
        "CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
        "CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs "
        "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END",
    ],
}
DOWN = {
    "postgresql": [
        "DROP TRIGGER audit_logs_no_truncate ON audit_logs",
        "DROP TRIGGER audit_logs_no_change ON audit_logs",
        "DROP FUNCTION audit_logs_append_only()",
    ],
    "sqlite": ["DROP TRIGGER audit_logs_no_delete", "DROP TRIGGER audit_logs_no_update"],
}


def upgrade() -> None:
    for statement in UP.get(op.get_bind().dialect.name, []):
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWN.get(op.get_bind().dialect.name, []):
        op.execute(statement)
