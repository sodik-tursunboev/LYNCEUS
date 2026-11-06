"""email quarantine actions (M6b, ADR-017 addendum)

Adds the action kind MAIL_QUARANTINE and two columns used only by it: the provider (gmail or
outlook) and the provider's own message id, which is needed to find the message again. The id is
never returned by the API or written to a log, and it is cleared when the message is restored.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-06 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # batch mode: plain ALTERs on PostgreSQL, copy-and-move on SQLite (which cannot alter CHECKs)
    with op.batch_alter_table("actions") as batch:
        batch.add_column(sa.Column("provider", sa.String(length=16), nullable=True))
        batch.add_column(sa.Column("mail_ref", sa.String(length=512), nullable=True))
        batch.drop_constraint(op.f("ck_actions_kind_valid"), type_="check")
        batch.create_check_constraint(
            op.f("ck_actions_kind_valid"), "kind IN ('FILE_QUARANTINE', 'MAIL_QUARANTINE')"
        )
        batch.create_check_constraint(
            op.f("ck_actions_provider_valid"),
            "(kind = 'FILE_QUARANTINE' AND provider IS NULL AND mail_ref IS NULL) "
            "OR (kind = 'MAIL_QUARANTINE' AND provider IS NOT NULL "
            "AND provider IN ('gmail', 'outlook'))",
        )


def downgrade() -> None:
    # Email actions cannot exist before this revision: they are removed (their audit rows stay).
    op.execute("DELETE FROM actions WHERE kind = 'MAIL_QUARANTINE'")
    with op.batch_alter_table("actions") as batch:
        batch.drop_constraint(op.f("ck_actions_provider_valid"), type_="check")
        batch.drop_constraint(op.f("ck_actions_kind_valid"), type_="check")
        batch.create_check_constraint(op.f("ck_actions_kind_valid"), "kind IN ('FILE_QUARANTINE')")
        batch.drop_column("mail_ref")
        batch.drop_column("provider")
