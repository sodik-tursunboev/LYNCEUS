"""re-check alerts (DA5 Phase 3, item 1)

`retro_alerts`: a link stored earlier that a threat feed listed afterwards. One row per reference
(`sha256:<url hash>` or `host:<keyed host hash>`) and feed, so a rerun adds nothing. It points at
the verdict the link got when first seen and never changes it. No URL text, no host name.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-22 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retro_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ref", sa.String(length=80), nullable=False),
        sa.Column("feed", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("verdict_id", sa.Uuid(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("listed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("kind IN ('url', 'host')", name=op.f("ck_retro_alerts_kind_valid")),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.id"],
            name=op.f("fk_retro_alerts_verdict_id_verdicts"),
            ondelete="CASCADE",
        ),  # fmt: skip
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retro_alerts")),
        sa.UniqueConstraint("ref", "feed", name=op.f("uq_retro_alerts_ref")),
    )
    op.create_index(
        op.f("ix_retro_alerts_verdict_id"), "retro_alerts", ["verdict_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_retro_alerts_verdict_id"), table_name="retro_alerts")
    op.drop_table("retro_alerts")
