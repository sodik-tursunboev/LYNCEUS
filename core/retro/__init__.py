"""Re-check (DA5 Phase 3, item 1): a link judged UNKNOWN or BENIGN yesterday may be listed today.

When a threat feed is updated, what it ADDED (core/intel/feeds.py, `on_new`) is matched to the links
this computer stored in the last 30 days: pages that were analysed (`artifacts`) and links inside
messages and files (`extracted_urls`). Matching uses hashes only: the SHA-256 of the exact address,
and the keyed host hash (ADR-007) where the feed lists the host of some address. Nothing keeps URL
text, and nothing here asks anyone anything.

For each new match one `retro_alerts` row is written (unique on reference and feed, so a rerun adds
nothing) and one audit line. The row points at the verdict the link got when it was first seen; that
verdict is never edited. A link on a host the popular list or a brand's official list knows raises
nothing. The agent's toast and the console list are later steps: `alerts()` is the read side.

Limits: the address hash stored for a page keeps its `#fragment`, a feed's does not, so only an
address without a fragment matches by hash (the host still matches). A feed says nothing about when
an entry was listed: `listed_at` is the update that first carried it. A check that fails (database
down) is not repeated, because those entries are no longer new at the next update.
"""

import logging
import uuid
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, insert, select
from sqlalchemy.exc import IntegrityError

from core.db import audit, hosts
from core.db import models as db
from core.intel.feeds import _host_listing_is_meaningful
from core.urls import popular, psl
from rules.url.data import official_domains

log = logging.getLogger(__name__)
WINDOW = timedelta(days=30)
ACTOR = "core"

_Seen = tuple[str, str | None, str | None, datetime, uuid.UUID, str]  # see _stored()


def _known(host: str | None) -> bool:
    """A host the popular list or a brand's official list knows: a listing there is not raised."""
    if not host or host == hosts.UNREADABLE:
        return False
    registered = psl.lookup(host).registered_domain
    return bool(registered) and (popular.is_popular(registered) or registered in official_domains())


def _utc(at: datetime) -> datetime:
    return at if at.tzinfo else at.replace(tzinfo=UTC)  # SQLite hands back naive UTC


def _stored(engine: Engine, since: datetime) -> list[_Seen]:
    """(address hash, host tag, sealed host, first seen, verdict id, verdict state), oldest first:
    analysed pages, then the links found inside messages and files."""
    page = (
        select(db.Artifact.sha256, db.Artifact.host_tag, db.Artifact.host)
        .where(db.Artifact.kind == "URL")
        .add_columns(db.Event.observed_at, db.Verdict.id, db.Verdict.state)
        .join(db.Event, db.Event.id == db.Artifact.event_id)
        .join(db.Verdict, db.Verdict.artifact_id == db.Artifact.id)
        .where(db.Event.observed_at >= since)
    )
    link = (
        select(db.ExtractedUrl.url_sha256, db.Domain.name, db.Domain.sealed_name)
        .select_from(db.ExtractedUrl)
        .outerjoin(db.Domain, db.Domain.id == db.ExtractedUrl.domain_id)
        .add_columns(db.Event.observed_at, db.Verdict.id, db.Verdict.state)
        .join(db.Artifact, db.Artifact.id == db.ExtractedUrl.artifact_id)
        .join(db.Event, db.Event.id == db.Artifact.event_id)
        .join(db.Verdict, db.Verdict.artifact_id == db.Artifact.id)
        .where(db.Event.observed_at >= since)
    )
    with engine.connect() as c:
        rows = [(*r[:3], _utc(r[3]), r[4], r[5]) for q in (page, link) for r in c.execute(q)]
    return sorted(rows, key=lambda r: r[3])


def raise_alerts(
    engine: Engine,
    feed: str,
    new_urls: Collection[str],
    new_hosts: Collection[str],
    listed_at: datetime,
) -> int:
    """Match what `feed` just added to the links stored in the last 30 days. Returns the number of
    alerts added. Idempotent: a reference already raised for this feed is skipped."""
    stored = _stored(engine, listed_at - WINDOW)
    if not stored:
        return 0
    tags = {t: h for h in new_hosts if (t := hosts.tag(h))}
    hits: dict[str, tuple[str, datetime, uuid.UUID, str]] = {}  # ref -> kind, seen, verdict, state
    for sha, tag, sealed, seen_at, verdict_id, state in stored:  # oldest first: it keeps the first
        if sha in new_urls:
            if _known(hosts.reveal(sealed)):
                continue
            ref, kind = f"sha256:{sha}", "url"
        elif tag in tags:
            if _known(tags[tag]) or not _host_listing_is_meaningful(tags[tag]):
                continue  # a listing on a shared or official host says little about the host
            ref, kind = f"host:{tag}", "host"
        else:
            continue
        hits.setdefault(ref, (kind, seen_at, verdict_id, state))
    with engine.connect() as c:
        raised = set(c.scalars(select(db.RetroAlert.ref).where(db.RetroAlert.feed == feed)))
    added = 0
    for ref, (kind, seen_at, verdict_id, state) in hits.items():
        if ref in raised:
            continue
        alert_id = uuid.uuid4()
        audit.record(  # first: an alert nobody can trace is never raised
            engine, ACTOR, "retro.listed", "retro_alert",
            {"feed": feed, "match": kind, "ref": ref, "verdict": state,
             "first_seen_at": seen_at.isoformat(), "listed_at": listed_at.isoformat()},
            target_id=alert_id,
        )  # fmt: skip
        try:
            with engine.begin() as c:
                c.execute(
                    insert(db.RetroAlert).values(
                        id=alert_id, ref=ref, feed=feed, kind=kind, verdict_id=verdict_id,
                        first_seen_at=seen_at, listed_at=listed_at,
                    )
                )  # fmt: skip
        except IntegrityError:  # another writer raised it first
            continue
        added += 1
    if added:
        log.info("%d stored link(s) are now listed by %s", added, feed)
    return added


def alerts(engine: Engine, limit: int = 100) -> list[dict[str, Any]]:
    """Newest first, for the console and the agent: which feed, when it listed the link, when the
    link was first seen and what verdict it got then (the verdict itself stays as it was)."""
    q = (
        select(
            db.RetroAlert.id,
            db.RetroAlert.feed,
            db.RetroAlert.kind,
            db.RetroAlert.listed_at,
            db.RetroAlert.first_seen_at,
            db.RetroAlert.verdict_id,
            db.Verdict.state,
        )  # fmt: skip
        .join(db.Verdict, db.Verdict.id == db.RetroAlert.verdict_id)
        .order_by(db.RetroAlert.listed_at.desc(), db.RetroAlert.first_seen_at.desc())
        .limit(limit)
    )
    with engine.connect() as c:
        return [
            {"id": str(r.id), "feed": r.feed, "match": r.kind,
             "listed_at": _utc(r.listed_at).isoformat(),
             "first_seen_at": _utc(r.first_seen_at).isoformat(),
             "verdict_id": str(r.verdict_id), "verdict_state": r.state}
            for r in c.execute(q)
        ]  # fmt: skip
