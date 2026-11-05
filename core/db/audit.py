"""Append-only audit records (convention only: see KNOWN_LIMITATIONS). Redacted before storing."""

from collections.abc import Mapping
from typing import Any

from sqlalchemy import Engine, insert

from core.db import models as db


def record(
    engine: Engine, actor: str, action: str, target_type: str, detail: Mapping[str, Any]
) -> None:
    with engine.begin() as c:
        c.execute(
            insert(db.AuditLog).values(
                actor=actor, action=action, target_type=target_type, detail=dict(detail)
            )
        )
