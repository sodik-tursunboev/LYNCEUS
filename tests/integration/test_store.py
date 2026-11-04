"""What reaches the database, and above all what does not (M1 decision D2)."""

import pytest
from sqlalchemy import Engine, func, select

from core.contracts import EventSource, VerdictState
from core.db import models as db
from core.db.models import Base
from core.db.store import save_analysis
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


def test_a_failed_save_leaves_nothing_behind(migrated: Engine) -> None:
    a = analyze_url("https://paypal-login.test/")
    save_analysis(migrated, a, EventSource.API)
    with pytest.raises(Exception):  # noqa: B017, PT011  same ids again: the DB refuses it
        save_analysis(migrated, a, EventSource.API)
    assert count(migrated, db.Event) == 1 and count(migrated, db.Verdict) == 1
