"""feedback on verdicts (H1 B3)

One row per verdict: false_alarm, missed or correct, given by the person. Every answer is also in
the audit log. Together with `detections` it shows which rules are noisy on this machine.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-14 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "feedback",
        sa.Column("verdict_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(length=16), nullable=False),
        sa.Column("given_by", sa.String(length=16), nullable=False),
        sa.Column(
            "given_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "label IN ('false_alarm', 'missed', 'correct')", name=op.f("ck_feedback_label_valid")
        ),
        sa.CheckConstraint("given_by IN ('user')", name=op.f("ck_feedback_given_by_valid")),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.id"],
            name=op.f("fk_feedback_verdict_id_verdicts"),
            ondelete="CASCADE",
        ),  # fmt: skip
        sa.PrimaryKeyConstraint("verdict_id", name=op.f("pk_feedback")),
    )
    op.create_index(op.f("ix_feedback_label"), "feedback", ["label"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_feedback_label"), table_name="feedback")
    op.drop_table("feedback")
