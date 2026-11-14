"""sealed hosts (ADR-007, H1 A8)

`artifacts.host` holds DPAPI-sealed text (longer than a host name, and no longer worth an index);
`artifacts.host_tag` is its keyed hash for lookups. `domains.name` and `registered_domain` become
keyed hashes and `domains.sealed_name` keeps the sealed name. Schema only: values written before
are sealed by `python -m core.db.hosts seal-existing`, which the core also runs at start.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-14 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("artifacts") as batch:
        batch.drop_index(op.f("ix_artifacts_host"))
        batch.alter_column("host", type_=sa.Text(), existing_type=sa.String(length=253))
        batch.add_column(sa.Column("host_tag", sa.String(length=64), nullable=True))
        batch.create_index(op.f("ix_artifacts_host_tag"), ["host_tag"], unique=False)
    with op.batch_alter_table("domains") as batch:
        batch.add_column(sa.Column("sealed_name", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("domains") as batch:
        batch.drop_column("sealed_name")
    with op.batch_alter_table("artifacts") as batch:
        batch.drop_index(op.f("ix_artifacts_host_tag"))
        batch.drop_column("host_tag")
        batch.alter_column("host", type_=sa.String(length=253), existing_type=sa.Text())
        batch.create_index(op.f("ix_artifacts_host"), ["host"], unique=False)
