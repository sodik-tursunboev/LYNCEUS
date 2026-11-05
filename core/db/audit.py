"""Append-only audit records (convention only: see KNOWN_LIMITATIONS). Redacted before storing."""

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, insert

from core.db import models as db


def record(
    engine: Engine,
    actor: str,
    action: str,
    target_type: str,
    detail: Mapping[str, Any],
    target_id: UUID | None = None,
) -> None:
    with engine.begin() as c:
        c.execute(
            insert(db.AuditLog).values(
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
                detail=dict(detail),
            )
        )


def record_anywhere(
    engine: Engine | None, data_dir: Path, actor: str, action: str, target_type: str,
    detail: Mapping[str, Any],
) -> str:  # fmt: skip
    """The audit record goes to the database when there is one, else to `audit.jsonl` in the data
    folder. Returns where it went; raises if it went nowhere (an unauditable action is refused)."""
    if engine is not None:
        try:
            record(engine, actor, action, target_type, detail)
            return "database"
        except Exception:  # noqa: BLE001, S110  (fall through to the file)
            pass
    data_dir.mkdir(parents=True, exist_ok=True)
    line = {"at": datetime.now(UTC).isoformat(), "actor": actor, "action": action,
            "target_type": target_type, "detail": dict(detail)}  # fmt: skip
    with (data_dir / "audit.jsonl").open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(line, sort_keys=True) + "\n")
    return "file"
