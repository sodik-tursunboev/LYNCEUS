from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

ROOT = Path(__file__).parents[2]


def alembic_config(conn: sa.Connection) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["connection"] = conn
    return cfg


def upgrade(engine: sa.Engine) -> None:
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")
