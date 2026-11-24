"""DA5 re-check: a feed update that lists a link stored earlier raises one retro alert, once, and
never touches the old verdict. A throwaway SQLite database and a fake feed served by
httpx.MockTransport (the product's own `sync` runs): no socket is ever opened."""

import asyncio
import bz2
import json
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, create_engine, select, update

from core.contracts import ArtifactKind, EventSource
from core.db import models as db
from core.db.store import _write, save_analysis
from core.detection.engine import analyze_url
from core.email.engine import ExtractedRef
from core.intel.feeds import FEEDS, FeedStore, sync
from core.intel.http import make_client
from core.retro import alerts, raise_alerts
from core.urls import popular
from core.urls.parse import ParsedUrl, parse_url

PHISH = FEEDS["phishtank"]
SEEN = "http://evil-shop.test/login"
UNRELATED = "http://unrelated-listing.test/x"


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    eng = create_engine(f"sqlite:///{tmp_path / 'retro.db'}")
    db.Base.metadata.create_all(eng)
    return eng


@pytest.fixture
def store(tmp_path: Path) -> FeedStore:
    return FeedStore(tmp_path / "feeds")


def refresh(engine: Engine, store: FeedStore, urls: list[str], at: datetime | None = None) -> None:
    body = bz2.compress(json.dumps([{"url": u} for u in urls]).encode())
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=body))

    async def go() -> None:
        async with make_client(transport) as client:
            out = await sync(
                PHISH, store, client, now=at or datetime.now(UTC), force=True,
                on_new=partial(raise_alerts, engine),
            )  # fmt: skip
            assert out.status == "updated"

    asyncio.run(go())


def seen(engine: Engine, url: str = SEEN) -> None:
    save_analysis(engine, analyze_url(url), EventSource.BROWSER)


def rows(engine: Engine, table: Any) -> list[Any]:
    with engine.connect() as c:
        return [tuple(r) for r in c.execute(select(table))]


def listed_once(engine: Engine, store: FeedStore, listing: str = SEEN) -> None:
    seen(engine)
    refresh(engine, store, [UNRELATED])  # an earlier snapshot, so the next update has a diff
    assert alerts(engine) == []
    refresh(engine, store, [UNRELATED, listing])


@pytest.mark.parametrize(
    ("listing", "kind"),
    [(SEEN, "url"), ("http://evil-shop.test/kit/other.php", "host")],
    ids=["the exact address", "another address on the host"],
)
def test_a_new_listing_of_a_stored_host_raises_one_retro_event(
    engine: Engine, store: FeedStore, listing: str, kind: str
) -> None:
    before = datetime.now(UTC)
    listed_once(engine, store, listing)
    (alert,) = alerts(engine)
    verdict = rows(engine, db.Verdict)[0]
    assert (alert["feed"], alert["match"]) == ("phishtank", kind)
    assert alert["verdict_id"] == str(verdict[0]) and alert["verdict_state"] == verdict[2]
    assert before - timedelta(seconds=5) <= datetime.fromisoformat(alert["first_seen_at"])
    assert datetime.fromisoformat(alert["first_seen_at"]) <= datetime.fromisoformat(
        alert["listed_at"]
    )


def test_a_rerun_raises_nothing_more(engine: Engine, store: FeedStore) -> None:
    listed_once(engine, store)
    refresh(engine, store, [UNRELATED, SEEN])  # the same list again: nothing is new
    store.path("phishtank").unlink()  # the snapshot is lost: every entry looks new again
    refresh(engine, store, [UNRELATED, SEEN])
    refresh(engine, store, [UNRELATED, SEEN, "http://another.test/"])
    assert len(alerts(engine)) == 1 and len(rows(engine, db.RetroAlert)) == 1
    link = parse_url(SEEN)
    assert isinstance(link, ParsedUrl)
    assert raise_alerts(engine, "phishtank", {link.url_sha256}, set(), datetime.now(UTC)) == 0
    assert len(alerts(engine)) == 1


def test_an_old_verdict_is_never_edited(engine: Engine, store: FeedStore) -> None:
    seen(engine)
    kept = {t: rows(engine, t) for t in (db.Event, db.Artifact, db.Verdict, db.Detection)}
    refresh(engine, store, [UNRELATED])
    refresh(engine, store, [UNRELATED, SEEN])
    assert len(alerts(engine)) == 1
    assert {t: rows(engine, t) for t in kept} == kept


@pytest.mark.parametrize(
    ("page", "listings"),
    [
        ("http://www.popular-site.test/page", ["http://www.popular-site.test/page"]),
        ("http://www.popular-site.test/page", ["http://www.popular-site.test/other"]),
        ("https://www.paypal.com/signin", ["https://www.paypal.com/signin"]),
        ("https://www.paypal.com/signin", ["https://www.paypal.com/other"]),
    ],
    ids=["popular, exact", "popular, host", "official, exact", "official, host"],
)
def test_a_host_the_popular_list_knows_is_never_raised(
    engine: Engine, store: FeedStore, page: str, listings: list[str]
) -> None:
    popular.use(frozenset({"popular-site.test"}))
    seen(engine, page)
    refresh(engine, store, [UNRELATED])
    refresh(engine, store, [UNRELATED, *listings])
    assert alerts(engine) == [] and rows(engine, db.AuditLog) == []
    if "popular" in page:  # the control: it is the list that held it back
        popular.use(frozenset())
        link = parse_url(listings[0])
        assert isinstance(link, ParsedUrl) and link.host
        assert (
            raise_alerts(engine, "phishtank", {link.url_sha256}, {link.host}, datetime.now(UTC))
            >= 1
        )


def test_the_event_is_audited(engine: Engine, store: FeedStore) -> None:
    listed_once(engine, store)
    (alert,) = alerts(engine)
    (row,) = [r for r in rows(engine, db.AuditLog) if r[3] == "retro.listed"]
    audit = dict(zip(db.AuditLog.__table__.columns.keys(), row, strict=True))
    assert str(audit["target_id"]) == alert["id"] and audit["target_type"] == "retro_alert"
    assert audit["actor"] == "core"
    detail = audit["detail"]
    assert (detail["feed"], detail["match"], detail["verdict"]) == (
        "phishtank", "url", alert["verdict_state"]
    )  # fmt: skip
    assert "evil-shop" not in json.dumps(detail) and "login" not in json.dumps(detail)


def test_a_link_found_inside_a_message_is_matched_too(engine: Engine, store: FeedStore) -> None:
    link = parse_url("http://mail-link.test/pay")
    assert isinstance(link, ParsedUrl)
    mail = analyze_url("http://sender.test/")  # any analysis: it carries a verdict to attach
    ref = ExtractedRef(
        url_sha256=link.url_sha256, host=link.host, registered_domain=link.registered_domain,
        position=0,
    )  # fmt: skip
    _write(engine, mail.verdict, mail.evidence, ArtifactKind.EMAIL, "e" * 64, None,
           EventSource.API, (ref,))  # fmt: skip
    refresh(engine, store, [UNRELATED])
    refresh(engine, store, [UNRELATED, "http://mail-link.test/pay"])
    (alert,) = alerts(engine)
    assert alert["match"] == "url" and alert["verdict_id"] == str(mail.verdict.id)


def test_a_sighting_older_than_thirty_days_is_not_matched(engine: Engine, store: FeedStore) -> None:
    seen(engine)
    with engine.begin() as c:
        c.execute(update(db.Event).values(observed_at=datetime.now(UTC) - timedelta(days=31)))
    refresh(engine, store, [UNRELATED])
    refresh(engine, store, [UNRELATED, SEEN])
    assert alerts(engine) == []
