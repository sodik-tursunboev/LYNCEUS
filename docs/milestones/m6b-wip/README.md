# M6b work in progress (not part of the build)

These two files belong to email quarantine (`docs/milestones/M6b.md`) but are **not wired in yet**, so they are kept as text, not as Python: they are not imported, linted or tested.

- `quarantine.py.txt`: the runner in the core that carries out approved mail moves and restores. It needs the response service to learn `mail_work()` and a `mail_ref` argument on `transition()`.
- `0003_mail_actions.py.txt`: the Alembic migration (kind `MAIL_QUARANTINE`, columns `provider` and `mail_ref`). It needs the ORM model changed to match, and a PostgreSQL run (Docker was not running when this was written).

When M6b is built, move them to `core/mailbox/quarantine.py` and `core/db/migrations/versions/0003_mail_actions.py`.
