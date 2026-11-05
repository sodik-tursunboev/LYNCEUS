"""The initial migration is frozen at v0.1 (ADR-006): from here on the schema changes only by a new
migration, because a database may already have been built from this one."""

import hashlib
from pathlib import Path

FIRST = (
    Path(__file__).parents[2] / "core" / "db" / "migrations" / "versions" / "0001_initial_schema.py"
)
PINNED = (
    "a16dbfc71ae348922ac981d39fb6a94080edd9e4dddb0bff8e1f352af51648c8"  # pragma: allowlist secret
)


def test_the_initial_migration_has_not_been_edited_since_v0_1() -> None:
    digest = hashlib.sha256(FIRST.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    assert digest == PINNED, (
        "0001 is frozen at v0.1. Do not edit it: add 0002 with `alembic revision --autogenerate`."
    )
