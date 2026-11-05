"""JSON-lines export: what is in a line, that it is stable and bounded, and that no URL or message
text can be in it (the database never had any)."""

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from mailhelp import PHISH_LINK, analyze, eml
from sqlalchemy import Engine, create_engine

import core.export as export
from core.contracts import EventSource, ProviderResult, ProviderStatus, VerdictState
from core.db import models as db
from core.db.store import save_analysis, save_email_analysis
from core.detection.engine import analyze_url
from core.export import ExportRecord, export_records, main, write_jsonl
from core.intel.base import IntelOutcome, IntelResult
from core.risk.correlate import correlate

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
MARKED = "https://paypal.com@PATHMARK-secure.test/login.php?token=QUERYMARK#FRAGMARK"


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    url = f"sqlite:///{tmp_path / 'mirage.db'}"
    e = create_engine(url)
    db.Base.metadata.create_all(e)
    return e


def listed_by_phishtank() -> IntelOutcome:
    result = ProviderResult(
        provider="phishtank", status=ProviderStatus.OK, state=VerdictState.MALICIOUS,
        queried_at=NOW, latency_ms=2, provenance="PhishTank, 3 entries",
        detail="this URL is on the list",
    )  # fmt: skip
    facts = {"listed": "url", "feed": "phishtank"}
    failed = ProviderResult(
        provider="openphish", status=ProviderStatus.TIMEOUT, queried_at=NOW, latency_ms=2000,
        provenance="OpenPhish feed", detail="no answer in time",
    )  # fmt: skip
    return IntelOutcome((IntelResult(result, facts), IntelResult(failed, {})), ())


def fill(engine: Engine) -> list[str]:
    """A URL with intelligence, a plain URL, and a message: three verdicts, in this time order."""
    first = correlate(analyze_url(MARKED), listed_by_phishtank())
    save_analysis(engine, first, EventSource.API)
    save_analysis(engine, analyze_url("https://www.example.com/page"), EventSource.API)
    mail = analyze(
        eml(sender='"PayPal Support" <help@paypal-login.test>', subject="SUBJMARK", html=PHISH_LINK)
    )
    save_email_analysis(engine, mail, EventSource.API)
    return [first.verdict.explanation, "", mail.report.verdict.explanation]


def lines(engine: Engine, **kw: object) -> list[str]:
    out = io.StringIO()
    write_jsonl(export_records(engine, **kw), out)  # type: ignore[arg-type]
    return out.getvalue().splitlines()


def test_an_empty_database_exports_nothing(engine: Engine) -> None:
    assert lines(engine) == []


def test_one_line_per_verdict_in_time_order_each_a_valid_record(engine: Engine) -> None:
    fill(engine)
    out = lines(engine)
    records = [ExportRecord.model_validate_json(line) for line in out]
    assert len(records) == 3
    assert [r.timestamp for r in records] == sorted(r.timestamp for r in records)
    assert [r.mirage.artifact.kind for r in records] == ["URL", "URL", "EMAIL"]


def test_fields_follow_the_documented_mapping(engine: Engine) -> None:
    fill(engine)
    flagged, quiet, mail = (json.loads(line) for line in lines(engine))
    assert flagged["event"]["kind"] == "alert" and flagged["event"]["category"] == ["threat", "web"]
    assert flagged["event"]["severity"] == 3 and flagged["event"]["risk_score"] >= 80
    assert (
        flagged["event"]["dataset"] == "mirage.verdict" and flagged["event"]["action"] == "verdict"
    )
    assert flagged["url"] == {
        "domain": "pathmark-secure.test"
    }  # the host, lower-cased: never a path
    assert flagged["threat"]["technique"]["id"] == sorted(set(flagged["threat"]["technique"]["id"]))
    assert "T1566.002" in flagged["threat"]["technique"]["id"]
    assert [s["rule_id"] for s in flagged["mirage"]["signals"]] == sorted(
        s["rule_id"] for s in flagged["mirage"]["signals"]
    )
    assert {p["provider"]: p["status"] for p in flagged["mirage"]["provider_results"]} == {
        "openphish": "TIMEOUT",
        "phishtank": "OK",
    }
    assert quiet["event"]["kind"] == "event" and quiet["event"]["severity"] == 1
    assert "risk_score" not in quiet["event"] and "threat" not in quiet
    assert mail["event"]["category"] == ["threat", "email"]
    assert len(mail["file"]["hash"]["sha256"]) == 64 and "url" not in mail
    assert flagged["mirage"]["schema_version"] == 1 and flagged["@timestamp"]


def test_the_export_is_deterministic(engine: Engine) -> None:
    fill(engine)
    assert lines(engine) == lines(engine)


def test_no_url_or_message_text_can_be_in_the_export(engine: Engine) -> None:
    fill(engine)
    text = "\n".join(lines(engine))
    for private in (
        "PATHMARK",
        "QUERYMARK",
        "FRAGMARK",
        "SUBJMARK",
        "PayPal Support",
        "help@",
        "login.php",
    ):
        assert private not in text, private


def test_since_and_until_select_by_verdict_time(engine: Engine) -> None:
    fill(engine)
    stamps = [ExportRecord.model_validate_json(x).timestamp for x in lines(engine)]
    assert len(lines(engine, since=stamps[1])) == 2
    assert len(lines(engine, until=stamps[1])) == 1
    assert len(lines(engine, since=stamps[1], until=stamps[2])) == 1
    assert lines(engine, since=stamps[2] + timedelta(seconds=1)) == []


def test_reading_in_chunks_returns_every_verdict_once_in_order(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(7):
        save_analysis(engine, analyze_url(f"https://site{i}.example.com/p"), EventSource.API)
    whole = lines(engine)
    monkeypatch.setattr(export, "CHUNK", 2)
    assert lines(engine) == whole and len(whole) == 7
    assert len({json.loads(line)["event"]["id"] for line in whole}) == 7


def test_the_cli_needs_a_database_and_writes_a_file(
    engine: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MIRAGE_DATABASE_URL", raising=False)
    assert main([]) == 2 and "nothing to export" in capsys.readouterr().err
    fill(engine)
    monkeypatch.setenv("MIRAGE_DATABASE_URL", str(engine.url))
    target = tmp_path / "out.jsonl"
    assert main(["--out", str(target)]) == 0
    assert "3 verdicts written" in capsys.readouterr().err
    written = target.read_text(encoding="utf-8").splitlines()
    assert len(written) == 3 and written == lines(engine)
    assert main([]) == 0 and capsys.readouterr().out.splitlines() == written
