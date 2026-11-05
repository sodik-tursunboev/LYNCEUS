"""What reaches the database, and above all what does not (M1 decision D2)."""

import pytest
from mailhelp import analyze, eml
from sqlalchemy import Engine, func, select

from core.contracts import EventSource, VerdictState
from core.db import models as db
from core.db.models import Base
from core.db.store import save_analysis, save_email_analysis
from core.detection.engine import analyze_url


def count(engine: Engine, model: type[Base]) -> int:
    with engine.connect() as c:
        return int(c.scalar(select(func.count()).select_from(model)) or 0)


def test_saves_the_whole_analysis(migrated: Engine) -> None:
    a = analyze_url("https://paypal.com@secure-check.test/login.php")
    save_analysis(migrated, a, EventSource.API)

    n = len(a.verdict.signals)
    assert n >= 2
    assert (count(migrated, db.Event), count(migrated, db.Artifact)) == (1, 1)
    assert count(migrated, db.Verdict) == 1
    assert count(migrated, db.Detection) == n
    assert count(migrated, db.Evidence) == len(a.evidence) == n
    assert count(migrated, db.DetectionEvidence) == n

    with migrated.connect() as c:
        art = c.execute(select(db.Artifact)).one()
        ver = c.execute(select(db.Verdict)).one()
    assert art.host == "secure-check.test"
    assert a.url and art.sha256 == a.url.url_sha256 and art.ref == f"sha256:{art.sha256}"
    assert ver.state == a.verdict.state.value and ver.risk_score == a.verdict.risk_score
    assert ver.ruleset_version == a.verdict.ruleset_version
    assert ver.engine_version == a.verdict.engine_version


def test_no_url_text_reaches_any_table(migrated: Engine) -> None:
    url = (
        "https://paypal.com@PATHMARK.secure-check.test/PATHMARK/login.php"
        "?email=QUERYMARK%40example.test&next=http%3A%2F%2Fphish.invalid%2FTARGETMARK#FRAGMARK"
    )
    a = analyze_url(url)
    save_analysis(migrated, a, EventSource.API)
    assert a.verdict.signals
    with migrated.connect() as c:
        stored = [repr(row) for t in Base.metadata.sorted_tables for row in c.execute(select(t))]
    dump = "\n".join(stored)
    for secret in ("/PATHMARK", "QUERYMARK", "TARGETMARK", "FRAGMARK", "login.php", url):
        assert secret not in dump, secret
    assert count(migrated, db.ExtractedUrl) == 0


@pytest.mark.parametrize(
    ("raw", "reason"),
    [("http://ex ample.test/", "unparseable"), ("x" * 9000, "too_long")],
)
def test_unparseable_input_is_stored_by_hash_alone(migrated: Engine, raw: str, reason: str) -> None:
    a = analyze_url(raw)
    assert a.reason == reason
    save_analysis(migrated, a, EventSource.API)
    with migrated.connect() as c:
        art = c.execute(select(db.Artifact)).one()
        ver = c.execute(select(db.Verdict)).one()
    assert (art.host, art.sha256) == (None, a.input_sha256)
    assert (ver.state, ver.risk_score) == (VerdictState.UNKNOWN.value, None)


def test_a_hostile_host_length_is_dropped_not_fatal(migrated: Engine) -> None:
    a = analyze_url("https://" + "a." * 500 + "test/")
    save_analysis(migrated, a, EventSource.API)
    with migrated.connect() as c:
        assert c.execute(select(db.Artifact)).one().host is None


def test_the_refang_note_is_kept_as_evidence(migrated: Engine) -> None:
    a = analyze_url("hxxps://paypal-login[.]test/")
    assert "input_note" in {e.kind for e in a.evidence}
    assert set(a.verdict.evidence_ids) == {e.id for e in a.evidence}
    save_analysis(migrated, a, EventSource.API)
    with migrated.connect() as c:
        kinds = set(c.scalars(select(db.Evidence.kind)))
    assert "input_note" in kinds


def test_a_message_is_stored_by_hash_and_host_never_by_text(migrated: Engine) -> None:
    raw = eml(
        sender='"PayPal Support" <help@paypal-login.test>',
        subject="SUBJMARK",
        text="BODYMARK",
        html='<a href="https://paypal-login.test/PATHMARK?q=QUERYMARK">https://www.paypal.com/x</a>',
        attachments=[("FILEMARK.pdf.exe", b"MZ\x90\x00", "application/octet-stream")],
    )
    a = analyze(raw)
    n = len(a.report.verdict.signals)
    assert n >= 3 and a.urls
    save_email_analysis(migrated, a, EventSource.API)

    assert (count(migrated, db.Event), count(migrated, db.Artifact)) == (1, 1)
    assert count(migrated, db.Detection) == n and count(migrated, db.Evidence) == len(
        a.report.evidence
    )
    with migrated.connect() as c:
        art = c.execute(select(db.Artifact)).one()
        domains = set(c.scalars(select(db.Domain.name)))
        urls = c.execute(select(db.ExtractedUrl)).all()
        stored = [repr(row) for t in Base.metadata.sorted_tables for row in c.execute(select(t))]
    assert (art.kind, art.sha256, art.host) == ("EMAIL", a.input_sha256, None)
    assert "paypal-login.test" in domains and len(urls) == len(a.urls)
    assert all(u.url is None and len(u.url_sha256) == 64 for u in urls)
    dump = "\n".join(stored)
    for marker in ("SUBJMARK", "BODYMARK", "PATHMARK", "QUERYMARK", "FILEMARK", "help@", "Support"):
        assert marker not in dump, marker


def test_two_messages_to_one_host_share_one_domain_row(migrated: Engine) -> None:
    link = '<a href="https://shared-host.test/{}">x</a>'
    for i in range(2):
        save_email_analysis(migrated, analyze(eml(html=link.format(i))), EventSource.API)
    assert count(migrated, db.Artifact) == 2 and count(migrated, db.ExtractedUrl) == 2
    with migrated.connect() as c:
        assert list(c.scalars(select(db.Domain.name))) == ["shared-host.test"]


def test_an_unscored_message_verdict_is_stored_without_a_score(migrated: Engine) -> None:
    a = analyze(eml())  # no signals: UNKNOWN
    save_email_analysis(migrated, a, EventSource.API)
    with migrated.connect() as c:
        ver = c.execute(select(db.Verdict)).one()
    assert (ver.state, ver.risk_score) == ("UNKNOWN", None)


def test_a_failed_save_leaves_nothing_behind(migrated: Engine) -> None:
    a = analyze_url("https://paypal-login.test/")
    save_analysis(migrated, a, EventSource.API)
    with pytest.raises(Exception):  # noqa: B017, PT011  same ids again: the DB refuses it
        save_analysis(migrated, a, EventSource.API)
    assert count(migrated, db.Event) == 1 and count(migrated, db.Verdict) == 1
