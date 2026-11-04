"""Alembic environment. Online mode only.

URL: MIRAGE_DATABASE_URL, or an open connection handed in via config.attributes["connection"]
(tests do this, so a password never has to pass through alembic.ini).
"""

from alembic import context
from sqlalchemy import Connection, create_engine, pool

from core.config import Settings
from core.db.models import Base

config = context.config


def _migrate(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _migrate(connection)
        return
    url = Settings().database_url
    if url is None:
        raise SystemExit("MIRAGE_DATABASE_URL is not set (see .env.example)")
    engine = create_engine(url.get_secret_value(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        _migrate(conn)
        conn.commit()


if context.is_offline_mode():
    raise SystemExit("offline (SQL script) mode is not supported")
run_migrations_online()
