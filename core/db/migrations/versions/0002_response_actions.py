"""response actions and allow list (M6, ADR-018)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-05 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = "'FILE_QUARANTINE'"
STATES = "'PENDING', 'APPROVED', 'APPLIED', 'DISMISSED', 'FAILED', 'RESTORE_REQUESTED', 'RESTORED'"


def upgrade() -> None:
    op.create_table(
        "actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("verdict_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("file_ref", sa.String(length=32), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("decided_by", sa.String(length=16), nullable=True),
        sa.Column("reason", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(f"kind IN ({KINDS})", name=op.f("ck_actions_kind_valid")),
        sa.CheckConstraint(f"state IN ({STATES})", name=op.f("ck_actions_state_valid")),
        sa.CheckConstraint(
            "decided_by IS NULL OR decided_by IN ('user', 'policy')",
            name=op.f("ck_actions_decider"),
        ),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.id"],
            name=op.f("fk_actions_verdict_id_verdicts"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_actions")),
        sa.UniqueConstraint("file_ref", name=op.f("uq_actions_file_ref")),
    )
    op.create_index(op.f("ix_actions_sha256"), "actions", ["sha256"], unique=False)
    op.create_index(op.f("ix_actions_state"), "actions", ["state"], unique=False)
    op.create_index(op.f("ix_actions_verdict_id"), "actions", ["verdict_id"], unique=False)
    op.create_table(
        "allowlist",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_allowlist")),
        sa.UniqueConstraint("sha256", name=op.f("uq_allowlist_sha256")),
    )


def downgrade() -> None:
    op.drop_table("allowlist")
    op.drop_index(op.f("ix_actions_verdict_id"), table_name="actions")
    op.drop_index(op.f("ix_actions_state"), table_name="actions")
    op.drop_index(op.f("ix_actions_sha256"), table_name="actions")
    op.drop_table("actions")
