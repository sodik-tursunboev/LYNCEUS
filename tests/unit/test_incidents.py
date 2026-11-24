"""The incident view (DA5 phase 3, item 2): events linked into chains by shared keys, every edge
labelled, nothing edited, and a downloaded file's origin reading the site's stored verdict.
Seeded rows go through the core's own writer into throwaway SQLite databases."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from mailhelp import in_process_file
from sqlalchemy import Engine, create_engine, event, select

from core.contracts import ArtifactKind, VerdictState
from core.db import models as db
from core.files.engine import FileAnalysis, analyze_file
from core.incidents import LABELS, find_incidents, stored_origin
from core.urls import popular
from eval.incidents import SIGN, WEAK, Seeder, snapshot

pytestmark = pytest.mark.usefixtures("no_learned_model")  # about the rules and the keys only

U, S, M, B, E = (
    VerdictState.UNKNOWN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS, VerdictState.BENIGN,
    VerdictState.ERROR,
)  # fmt: skip
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
WINDOW = (T0 - timedelta(days=1), T0 + timedelta(days=30))
EXE = b"MZ\x90\x00" + b"\x00" * 60
LINK = "https://login-secure.phish.test/verify"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    made = create_engine(f"sqlite:///{tmp_path / 'incidents.db'}")
    db.Base.metadata.create_all(made)
    return made


def chain(s: Seeder, host: str = "login-secure.phish.test", start: float = 0) -> tuple[Any, ...]:
    """A flagged mail, the click on its link, and a download from that site."""
    link = f"https://{host}/verify"
    return (
        s.mail(at(start), [link], S, SIGN),
        s.click(at(start + 90), link, S, SIGN),
        s.download(at(start + 120), host, f"viewer-{host}", U, WEAK),
    )


# ---- the chain ---------------------------------------------------------------------------------


def test_a_mail_link_click_download_chain_is_linked_by_shared_keys(engine: Engine) -> None:
    s = Seeder(engine)
    m, c, f = chain(s)
    s.click(at(40), "https://unrelated.example.test/", U)  # noise between them
    (incident,) = find_incidents(engine, *WINDOW)

    assert [x.artifact_id for x in incident.members] == [m, c, f]
    assert [x.kind for x in incident.members] == [
        ArtifactKind.EMAIL, ArtifactKind.URL, ArtifactKind.FILE,
    ]  # fmt: skip
    by = {(e.earlier, e.later): e for e in incident.edges}
    assert set(by) == {(m, c), (c, f)}
    with engine.connect() as conn:  # the keys really are the same stored values
        sent = conn.scalar(
            select(db.ExtractedUrl.url_sha256).where(db.ExtractedUrl.artifact_id == m)
        )
        clicked = conn.scalar(select(db.Artifact.sha256).where(db.Artifact.id == c))
        tags = {
            i: conn.scalar(select(db.Artifact.host_tag).where(db.Artifact.id == i)) for i in (c, f)
        }
    assert sent == clicked and tags[c] == tags[f] and tags[c] is not None
    assert by[(m, c)].why == "mail_link_is_this_url" and by[(m, c)].key_prefix == sent[:12]
    assert by[(c, f)].why == "download_origin_is_this_host" and by[(c, f)].gap_seconds == 30
    assert by[(c, f)].key_prefix == tags[c][:12]
    assert incident.severity.category == "chain" and 0 < incident.severity.score <= 95
    assert incident.severity.flagged_members == 3


def test_every_edge_is_labelled(engine: Engine) -> None:
    s = Seeder(engine)
    m, c, f = chain(s)
    again = s.download(
        at(2 * 86_400), "elsewhere.phish.test", "viewer-login-secure.phish.test", S, SIGN
    )
    (incident,) = find_incidents(engine, *WINDOW)

    members = {x.artifact_id: x for x in incident.members}
    assert set(members) == {m, c, f, again}
    assert {e.why for e in incident.edges} == set(LABELS)  # all three kinds of edge are present
    for e in incident.edges:
        key, text = LABELS[e.why]
        assert e.key == key and e.text == text and text and len(e.key_prefix) == 12
        assert e.earlier in members and e.later in members
        assert e.gap_seconds == (members[e.later].at - members[e.earlier].at).total_seconds() >= 0
    assert {e.later for e in incident.edges} == {c, f, again}  # nothing is attached without one


# ---- what is not an incident -------------------------------------------------------------------


def test_benign_only_seeds_make_no_incident(engine: Engine) -> None:
    s = Seeder(engine)
    shapes = [
        (B, B, U, ()), (U, U, U, ()), (B, U, E, ()), (E, B, B, ()),
        (B, B, B, WEAK),  # an allowlisted site with weak signals is still benign
    ]  # fmt: skip
    for n, (mail, click, file, rules) in enumerate(shapes):
        host = f"quiet{n}.site.test"
        s.mail(at(n * 600), [f"https://{host}/a"], mail, rules if mail is B else ())
        s.click(at(n * 600 + 60), f"https://{host}/a", click, rules if click is B else ())
        s.download(at(n * 600 + 90), host, f"quiet-{n}", file, rules if file is B else ())
        s.download(at(n * 600 + 400), host, f"quiet-{n}", file, rules if file is B else ())
    assert find_incidents(engine, *WINDOW) == []

    # the same keys with something to warn about do make one: a flagged click, or a weak signal
    s.mail(at(9000), ["https://loud.site.test/a"], U)
    s.click(at(9060), "https://loud.site.test/a", M, SIGN)
    s.mail(at(9500), ["https://faint.site.test/a"], U)
    s.click(at(9560), "https://faint.site.test/a", U, WEAK)  # UNKNOWN, but with a signal
    assert len(find_incidents(engine, *WINDOW)) == 2


def test_decoy_events_are_not_linked(engine: Engine) -> None:
    s = Seeder(engine)
    popular.use(frozenset({"popular-cdn.test"}))
    flagged: dict[str, Any] = {"state": S, "rules": SIGN}
    decoys: list[Any] = []
    # the same site, but 31 minutes apart (the gap is 30)
    decoys += [s.click(at(0), "https://far.site.test/a", **flagged)]
    decoys += [s.download(at(31 * 60), "far.site.test", "far", U, WEAK)]
    # a popular site
    decoys += [s.click(at(0), "https://files.popular-cdn.test/a", **flagged)]
    decoys += [s.download(at(60), "files.popular-cdn.test", "popular", U, WEAK)]
    # a site that twelve events share
    decoys += [s.click(at(i), f"https://shared.site.test/p{i}", **flagged) for i in range(12)]
    decoys += [s.download(at(60), "shared.site.test", "shared", U, WEAK)]
    # events close in time with nothing in common
    decoys += [s.mail(at(0), ["https://one.site.test/a"], **flagged)]
    decoys += [s.click(at(5), "https://two.site.test/a", **flagged)]
    decoys += [s.download(at(10), "three.site.test", "three", U, WEAK)]
    # another address on the message's site, and the same address after the 7 day gap
    decoys += [s.mail(at(0), ["https://four.site.test/a"], **flagged)]
    decoys += [s.click(at(30), "https://four.site.test/b", **flagged)]
    decoys += [s.mail(at(0), ["https://five.site.test/a"], **flagged)]
    decoys += [s.click(at(8 * 86_400), "https://five.site.test/a", **flagged)]
    assert find_incidents(engine, *WINDOW) == []

    real = chain(s, start=3600)  # one true chain among them
    (incident,) = find_incidents(engine, *WINDOW)
    assert {x.artifact_id for x in incident.members} == set(real)
    assert not set(decoys) & {x.artifact_id for x in incident.members}

    # each decoy is one only because of its window or its list: loosen that and it links
    assert len(find_incidents(engine, *WINDOW, host_gap=timedelta(hours=1))) == 2
    assert len(find_incidents(engine, *WINDOW, hash_gap=timedelta(days=9))) == 2
    assert len(find_incidents(engine, *WINDOW, max_fanout=99)) == 2
    popular.use(frozenset())
    assert len(find_incidents(engine, *WINDOW)) == 2


def test_no_verdict_is_edited_by_a_chain(engine: Engine) -> None:
    s = Seeder(engine)
    chain(s)
    chain(s, "second.phish.test", 7200)
    s.click(at(50), "https://quiet.site.test/", U)
    before = snapshot(engine)
    assert all(
        before[t] for t in ("events", "artifacts", "verdicts", "detections", "extracted_urls")
    )

    statements: list[str] = []
    event.listen(
        engine,
        "before_cursor_execute",
        lambda *a: statements.append(a[2].lstrip().split()[0].upper()),
    )
    first = find_incidents(engine, *WINDOW)
    assert len(first) == 2 and set(statements) == {"SELECT"}  # it only ever reads
    assert snapshot(engine) == before  # every row of every table, verdicts included
    assert find_incidents(engine, *WINDOW) == first  # and the same answer again


# ---- a download's origin reads the site's stored verdict ---------------------------------------


def judge(host: str | None, engine: Engine | None = None, lookup: Any = None) -> FileAnalysis:
    return analyze_file(
        "setup.exe", len(EXE), hashlib.sha256(EXE).hexdigest(), EXE, run=in_process_file,
        origin_host=host, origin_lookup=lookup or (stored_origin(engine) if engine else None),
    )  # fmt: skip


def origin(a: FileAnalysis) -> Any:
    found = [s for s in a.report.verdict.signals if s.rule_id == "file.origin_flagged"]
    return found[0] if found else None


def test_the_downloads_origin_reads_the_hosts_stored_verdict(engine: Engine) -> None:
    s = Seeder(engine)
    caught = "files.caught-earlier.test"  # its bare address says nothing
    page = (("page.password_form", 0.9), ("list.url_known_bad", 0.99))
    s.click(at(0), f"https://{caught}/login", M, page)
    assert origin(judge(caught)) is None  # without the store: judged as before
    with_store = judge(caught, engine)
    sign = origin(with_store)
    assert sign is not None and sign.category == "origin" and sign.weight == pytest.approx(0.5)
    assert "MALICIOUS" in sign.description and "list.url_known_bad" in sign.description
    assert caught in sign.description  # said in the verdict, as the address-based sign always did
    assert with_store.report.verdict.state is VerdictState.SUSPICIOUS  # the file's own logic as is
    assert judge(caught).report.verdict.state is VerdictState.UNKNOWN

    # nothing stored for the host: today's behaviour, signs and all
    assert origin(judge("nothing-stored.test", engine)) is None
    assert origin(judge("paypal-login-secure.test", engine)) is not None
    assert "address Lynceus calls" in origin(judge("paypal-login-secure.test", engine)).description

    # only the latest verdict counts: a later one that does not flag ends it
    s.click(at(1), "https://later.site.test/a", M, page)
    s.click(at(2), "https://later.site.test/b", U)
    assert origin(judge("later.site.test", engine)) is None
    # a verdict about a file from that host says nothing about the host
    s.download(at(3), "fileonly.site.test", "other", M, page)
    assert origin(judge("fileonly.site.test", engine)) is None
    # a stored verdict that does not flag never cancels what the address says
    s.click(at(4), "https://paypal-login-secure.test/a", B)
    assert origin(judge("paypal-login-secure.test", engine)) is not None
    # both say it: both are named
    s.click(at(5), "https://paypal-login-secure.test/b", S, SIGN)
    both = origin(judge("paypal-login-secure.test", engine)).description
    assert "address Lynceus calls" in both and "had already judged it SUSPICIOUS" in both
    # a popular site's stored verdicts belong to one page on it, not to the site
    popular.use(frozenset({"popular-cdn.test"}))
    s.click(at(6), "https://docs.popular-cdn.test/one-bad-document", M, page)
    assert origin(judge("docs.popular-cdn.test", engine)) is None

    # the lookup failing changes nothing and costs no verdict
    def broken(_host: str) -> None:
        raise RuntimeError("database is down")

    assert origin(judge(caught, lookup=broken)) is None
    assert judge(caught, lookup=broken).report.verdict.state is VerdictState.UNKNOWN
