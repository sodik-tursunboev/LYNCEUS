"""Sites at rest (ADR-007, H1 A8): every stored text that can name a site is sealed with DPAPI.

What is sealed: an artifact's host, a rule's description, an evidence summary and a verdict's
explanation (they name hosts, e.g. "PayPal lookalike (paypa1.com)"), and a domain's name. Sealed
text is `h1:` + the DPAPI blob in base64, readable only by this Windows user on this computer: a
copied database, a backup or another account sees neither the sites nor anything a list of popular
sites could reverse. Lookups and grouping use a keyed hash (HMAC-SHA-256) whose key is itself kept
under DPAPI in the data folder (`hostkey.dpapi`).

Text written before sealing is read as it is (`reveal` passes it through) until
`python -m core.db.hosts seal-existing` (or the core at start) seals it. Audit rows are append-only,
so a host already written into an older audit row stays there; new rows carry the keyed hash.
Off Windows nothing is sealed (Lynceus runs on Windows only; the sandbox needs it).
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets as random
import threading
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, delete, select, update

PREFIX = "h1:"
KEY_FILE = "hostkey.dpapi"
UNREADABLE = "(sealed by another Windows user)"
_lock = threading.Lock()
_directory: Path | None = None
_key: bytes | None = None


def _dpapi() -> bool:
    return os.name == "nt"


def configure(directory: Path | None) -> None:
    """Where the keyed-hash key lives (the core's data folder). Unconfigured: a key for this process
    only, so tests and one-off tools never write a key file."""
    global _directory, _key
    with _lock:
        _directory, _key = directory, None


def _tag_key() -> bytes:
    global _key
    with _lock:
        if _key is not None:
            return _key
        if _directory is None or not _dpapi():
            _key = random.token_bytes(32)
            return _key
        from core.secrets import protect, unprotect

        path = _directory / KEY_FILE
        try:
            try:
                _key = unprotect(path.read_bytes())
            except FileNotFoundError:
                fresh = random.token_bytes(32)
                _directory.mkdir(parents=True, exist_ok=True)
                tmp = path.with_name(KEY_FILE + ".new")
                tmp.write_bytes(protect(fresh))
                tmp.replace(path)
                _key = fresh
        except OSError:
            # an unwritable or unreadable data folder must never stop a verdict or an audit record:
            # a key for this process only (lookups across restarts then miss; nothing is lost)
            logging.getLogger(__name__).warning(
                "the host key could not be kept; using one for this run"
            )
            _key = random.token_bytes(32)
        return _key


def seal(text: str | None) -> str | None:
    if text is None or text.startswith(PREFIX) or not _dpapi():
        return text
    from core.secrets import protect

    return PREFIX + base64.b64encode(protect(text.encode("utf-8"))).decode("ascii")


def reveal(text: str | None) -> str | None:
    if text is None or not text.startswith(PREFIX):
        return text  # written before sealing, or off Windows
    from core.secrets import unprotect

    try:
        return unprotect(base64.b64decode(text[len(PREFIX) :])).decode("utf-8")
    except (OSError, ValueError):
        return UNREADABLE


def tag(host: str | None) -> str | None:
    """The keyed hash of a host, for lookups and grouping: equal hosts give equal tags."""
    if host is None:
        return None
    return hmac.new(_tag_key(), host.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()


def seal_existing(engine: Engine, batch: int = 500) -> int:
    """Seal what was stored in plain text before (idempotent). Returns how many values it sealed."""
    from core.db import models as db

    if not _dpapi():
        return 0
    done = 0
    plain_columns: list[tuple[Any, Any]] = [
        (db.Artifact, db.Artifact.host), (db.Detection, db.Detection.description),
        (db.Evidence, db.Evidence.summary), (db.Verdict, db.Verdict.explanation),
    ]  # fmt: skip
    for model, column in plain_columns:
        while True:
            with engine.begin() as c:
                rows = c.execute(
                    select(model.id, column)
                    .where(column.is_not(None), ~column.startswith(PREFIX))
                    .limit(batch)
                ).all()
                for row_id, value in rows:
                    values = {column.key: seal(value)}
                    if model is db.Artifact:
                        values["host_tag"] = tag(value)
                    c.execute(update(model).where(model.id == row_id).values(**values))
            done += len(rows)
            if len(rows) < batch:
                break
    while True:  # domains: the plain name becomes its keyed hash, the name itself is kept sealed
        with engine.begin() as c:
            domain_rows = c.execute(
                select(db.Domain.id, db.Domain.name, db.Domain.registered_domain)
                .where(db.Domain.sealed_name.is_(None))
                .limit(batch)
            ).all()
            for row_id, name, registered in domain_rows:
                tagged = tag(name)
                twin = c.scalar(select(db.Domain.id).where(db.Domain.name == tagged))
                if (
                    twin is not None
                ):  # written again since the upgrade: keep that row, merge into it
                    c.execute(
                        update(db.ExtractedUrl)
                        .where(db.ExtractedUrl.domain_id == row_id)
                        .values(domain_id=twin)
                    )
                    c.execute(delete(db.Domain).where(db.Domain.id == row_id))
                    continue
                c.execute(
                    update(db.Domain).where(db.Domain.id == row_id).values(
                        name=tagged, sealed_name=seal(name), registered_domain=tag(registered),
                    )
                )  # fmt: skip
        done += len(domain_rows)
        if len(domain_rows) < batch:
            break
    return done


def main(argv: list[str] | None = None) -> int:
    import argparse

    from sqlalchemy import create_engine

    from core.config import Settings

    ap = argparse.ArgumentParser(
        prog="python -m core.db.hosts", description=__doc__.split("\n\n")[0]
    )
    ap.add_argument("command", choices=["seal-existing"])
    ap.parse_args(argv)
    settings = Settings()
    if settings.database_url is None:
        print("no database configured (LYNCEUS_DATABASE_URL)")
        return 2
    configure(settings.data_dir)
    engine = create_engine(settings.database_url.get_secret_value(), hide_parameters=True)
    print(f"sealed {seal_existing(engine)} stored value(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
