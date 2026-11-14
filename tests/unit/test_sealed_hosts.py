"""H1 A8 (ADR-007): stored texts that name sites are sealed with DPAPI, looked up by a keyed hash,
read back only through the API and the export, and values written before the upgrade are sealed."""

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, insert, select

from core.db import hosts
from core.db import models as db

pytestmark = pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows only")


def test_seal_and_reveal_round_trip_and_differ_each_time() -> None:
    a, b = hosts.seal("bank.example"), hosts.seal("bank.example")
    assert a and b and a != b and "bank" not in a  # a fresh blob every time
    assert hosts.reveal(a) == hosts.reveal(b) == "bank.example"
    assert hosts.seal(a) == a  # never sealed twice
    assert hosts.reveal("plain.example") == "plain.example"  # written before the upgrade
    assert hosts.reveal(hosts.PREFIX + "bm90IGEgYmxvYg==") == hosts.UNREADABLE


def test_tags_are_keyed_stable_and_case_blind(tmp_path: Path) -> None:
    hosts.configure(tmp_path)
    first = hosts.tag("Bank.Example")
    assert first == hosts.tag("bank.example") and len(first or "") == 64
    assert (tmp_path / hosts.KEY_FILE).exists() and b"bank" not in (
        tmp_path / hosts.KEY_FILE
    ).read_bytes()
    hosts.configure(tmp_path)  # a restart reads the same key back
    assert hosts.tag("bank.example") == first
    hosts.configure(tmp_path / "other")
    assert hosts.tag("bank.example") != first  # another key, another tag: not a plain hash
    hosts.configure(None)


def test_an_unwritable_data_folder_falls_back_to_a_key_for_this_run(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_text("a file where the folder should be", encoding="utf-8")
    hosts.configure(blocker)
    assert hosts.tag("x.example") == hosts.tag("x.example")  # works, and stays the same in this run
    hosts.configure(None)


def test_values_from_before_the_upgrade_are_sealed_and_twins_merged(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'l.db'}")
    db.Base.metadata.create_all(engine)
    hosts.configure(tmp_path)
    event, artifact, verdict, legacy, fresh = (uuid.uuid4() for _ in range(5))
    now = datetime.now(UTC)
    with engine.begin() as c:
        c.execute(insert(db.Event).values(id=event, source="API", observed_at=now))
        artifact_row = {"id": artifact, "event_id": event, "kind": "URL", "sha256": "0" * 64,
                        "ref": "sha256:x", "host": "legacy-host.test"}  # fmt: skip
        c.execute(insert(db.Artifact).values(**artifact_row))
        verdict_row = {
            "id": verdict, "artifact_id": artifact, "state": "SUSPICIOUS", "risk_score": 60,
            "confidence": "LOW", "recommended_response": "WARN", "applied_response": "NONE",
            "explanation": "lookalike (legacy-host.test)", "engine_version": "x",
            "ruleset_version": "x",
        }  # fmt: skip
        c.execute(insert(db.Verdict).values(**verdict_row))
        detection_row = {
            "id": uuid.uuid4(), "artifact_id": artifact, "verdict_id": verdict,
            "rule_id": "url.typosquat", "category": "impersonation", "weight": 0.6,
            "description": "PayPal lookalike (legacy-host.test)",
        }  # fmt: skip
        c.execute(insert(db.Detection).values(**detection_row))
        c.execute(insert(db.Domain).values(id=legacy, name="twin-host.test"))
        twin = {"id": fresh, "name": hosts.tag("twin-host.test"),
                "sealed_name": hosts.seal("twin-host.test")}  # fmt: skip
        c.execute(insert(db.Domain).values(**twin))
        link = {"id": uuid.uuid4(), "artifact_id": artifact, "domain_id": legacy,
                "url_sha256": "1" * 64}  # fmt: skip
        c.execute(insert(db.ExtractedUrl).values(**link))
    assert hosts.seal_existing(engine) >= 4
    with engine.connect() as c:
        dump = "\n".join(
            repr(r) for t in db.Base.metadata.sorted_tables for r in c.execute(select(t))
        )
        assert "legacy-host" not in dump and "twin-host" not in dump
        assert list(c.scalars(select(db.Domain.id))) == [
            fresh
        ]  # the legacy twin was merged into it
        assert list(c.scalars(select(db.ExtractedUrl.domain_id))) == [fresh]
        assert hosts.reveal(c.scalar(select(db.Artifact.host))) == "legacy-host.test"
    assert hosts.seal_existing(engine) == 0  # idempotent
    hosts.configure(None)
