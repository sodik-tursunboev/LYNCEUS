"""Verdict export as JSON lines (M3, decision D7): one verdict per line, for a SIEM to read.

    python -m core.export [--since ISO] [--until ISO] [--out FILE]

The field names follow the Elastic Common Schema where it has a field (`@timestamp`, `event.*`,
`threat.technique.id`, `url.domain`, `file.hash.sha256`); everything MIRAGE-specific sits under
`mirage`. It writes a file or standard output and sends nothing anywhere. What is exported is what
is stored: hashes, hosts, verdicts, signals, evidence summaries and provider results, never URL or
message text (ADR-007). Output is deterministic: the same database gives the same bytes.
"""

import argparse
import sys
from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import IO, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from core.config import Settings
from core.db import models as db

SCHEMA_VERSION = 1
CHUNK = 500
SEVERITY = {"MALICIOUS": 3, "SUSPICIOUS": 2, "UNKNOWN": 1, "BENIGN": 0, "ERROR": 0}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EventBlock(_Strict):
    kind: Literal["alert", "event"]
    category: list[str]
    type: list[str]
    action: str
    dataset: str
    id: str
    severity: int
    risk_score: int | None = None


class SignalOut(_Strict):
    rule_id: str
    category: str
    weight: float
    description: str
    attack: str | None = None


class ProviderOut(_Strict):
    provider: str
    status: str
    state: str | None = None
    queried_at: datetime
    latency_ms: int
    provenance: str
    detail: str | None = None


class VerdictOut(_Strict):
    state: str
    confidence: str
    recommended_response: str
    applied_response: str
    explanation: str
    engine_version: str
    ruleset_version: str


class ArtifactOut(_Strict):
    id: str
    kind: str
    sha256: str


class MirageBlock(_Strict):
    schema_version: int
    verdict: VerdictOut
    artifact: ArtifactOut
    signals: list[SignalOut]
    provider_results: list[ProviderOut]


class TechniqueBlock(_Strict):
    id: list[str]


class ThreatBlock(_Strict):
    technique: TechniqueBlock


class UrlBlock(_Strict):
    domain: str


class HashBlock(_Strict):
    sha256: str


class FileBlock(_Strict):
    hash: HashBlock


class ExportRecord(_Strict):
    timestamp: datetime = Field(alias="@timestamp")
    event: EventBlock
    mirage: MirageBlock
    threat: ThreatBlock | None = None
    url: UrlBlock | None = None
    file: FileBlock | None = None

    def line(self) -> str:
        return self.model_dump_json(by_alias=True, exclude_none=True)


def _record(
    v: db.Verdict,
    a: db.Artifact,
    detections: Sequence[db.Detection],
    providers: Sequence[db.ProviderResult],
) -> ExportRecord:
    techniques = sorted({d.attack for d in detections if d.attack})
    email = a.kind in ("EMAIL", "FILE")
    return ExportRecord(
        **{"@timestamp": v.created_at},
        event=EventBlock(
            kind="alert" if v.state in ("MALICIOUS", "SUSPICIOUS") else "event",
            category=["threat", "email" if a.kind == "EMAIL" else "file" if email else "web"],
            type=["info"],
            action="verdict",
            dataset="mirage.verdict",
            id=str(v.id),
            severity=SEVERITY[v.state],
            risk_score=v.risk_score,
        ),
        mirage=MirageBlock(
            schema_version=SCHEMA_VERSION,
            verdict=VerdictOut(
                state=v.state,
                confidence=v.confidence,
                recommended_response=v.recommended_response,
                applied_response=v.applied_response,
                explanation=v.explanation,
                engine_version=v.engine_version,
                ruleset_version=v.ruleset_version,
            ),
            artifact=ArtifactOut(id=str(a.id), kind=a.kind, sha256=a.sha256),
            signals=[
                SignalOut(
                    rule_id=d.rule_id,
                    category=d.category,
                    weight=d.weight,
                    description=d.description,
                    attack=d.attack,
                )  # fmt: skip
                for d in sorted(detections, key=lambda d: (d.rule_id, d.description))
            ],
            provider_results=[
                ProviderOut(
                    provider=p.provider,
                    status=p.status,
                    state=p.state,
                    queried_at=p.queried_at,
                    latency_ms=p.latency_ms,
                    provenance=p.provenance,
                    detail=p.detail,
                )  # fmt: skip
                for p in sorted(providers, key=lambda p: (p.provider, p.queried_at))
            ],
        ),
        threat=ThreatBlock(technique=TechniqueBlock(id=techniques)) if techniques else None,
        url=UrlBlock(domain=a.host) if a.host else None,
        file=FileBlock(hash=HashBlock(sha256=a.sha256)) if email else None,
    )


def export_records(
    engine: Engine, since: datetime | None = None, until: datetime | None = None
) -> Iterator[ExportRecord]:
    """Verdicts in time order (ties by id), read in chunks so a large history stays bounded."""
    last: tuple[datetime, object] | None = None
    while True:
        query = (
            select(db.Verdict, db.Artifact)
            .join(db.Artifact, db.Artifact.id == db.Verdict.artifact_id)
            .order_by(db.Verdict.created_at, db.Verdict.id)
            .limit(CHUNK)
        )
        if since is not None:
            query = query.where(db.Verdict.created_at >= since)
        if until is not None:
            query = query.where(db.Verdict.created_at < until)
        if last is not None:
            query = query.where(
                (db.Verdict.created_at > last[0])
                | ((db.Verdict.created_at == last[0]) & (db.Verdict.id > last[1]))
            )
        with Session(engine) as s:
            rows = s.execute(query).all()
            if not rows:
                return
            artifact_ids = [r[1].id for r in rows]
            verdict_ids = [r[0].id for r in rows]
            detections = list(
                s.scalars(select(db.Detection).where(db.Detection.verdict_id.in_(verdict_ids)))
            )
            providers = list(
                s.scalars(
                    select(db.ProviderResult).where(db.ProviderResult.artifact_id.in_(artifact_ids))
                )
            )
            s.expunge_all()  # plain objects: they are used after the session closes
        for v, a in rows:
            yield _record(
                v,
                a,
                [d for d in detections if d.verdict_id == v.id],
                [p for p in providers if p.artifact_id == a.id],
            )
        last = (rows[-1][0].created_at, rows[-1][0].id)


def write_jsonl(records: Iterator[ExportRecord], out: IO[str]) -> int:
    n = 0
    for record in records:
        out.write(record.line() + "\n")
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m core.export", description=__doc__)
    ap.add_argument("--since", type=datetime.fromisoformat, help="ISO time, inclusive")
    ap.add_argument("--until", type=datetime.fromisoformat, help="ISO time, exclusive")
    ap.add_argument("--out", help="file to write (default: standard output)")
    args = ap.parse_args(argv)
    url = Settings().database_url
    if url is None:
        print("MIRAGE_DATABASE_URL is not set: there is nothing to export", file=sys.stderr)
        return 2
    engine = create_engine(url.get_secret_value(), hide_parameters=True)
    records = export_records(engine, args.since, args.until)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            n = write_jsonl(records, f)
        print(f"{n} verdicts written to {args.out}", file=sys.stderr)
    else:
        write_jsonl(records, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
