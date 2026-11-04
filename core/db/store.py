"""Persist an analysis (M1 decision D2): hashes, host, verdict, signals, redacted evidence.

No URL text is stored: `artifacts.ref` is a hash reference until ADR-007 is signed off, and
`extracted_urls` stays empty. The whole analysis lands in one transaction or not at all.
"""

import uuid

from sqlalchemy import Engine, insert

from core.contracts import ArtifactKind, EventSource
from core.db import models as db
from core.detection.engine import UrlAnalysis

_MAX_HOST = 253  # longest DNS name, and the column size; longer hosts are hostile input


def save_analysis(engine: Engine, a: UrlAnalysis, source: EventSource) -> None:
    v = a.verdict
    digest = a.url.url_sha256 if a.url else a.input_sha256
    host = a.url.host if a.url else None
    event_id = uuid.uuid4()
    with engine.begin() as c:
        c.execute(
            insert(db.Event).values(id=event_id, source=source.value, observed_at=v.created_at)
        )
        c.execute(
            insert(db.Artifact).values(
                id=v.artifact_id,
                event_id=event_id,
                kind=ArtifactKind.URL.value,
                sha256=digest,
                ref=f"sha256:{digest}",
                host=host if host and len(host) <= _MAX_HOST else None,
            )
        )
        c.execute(
            insert(db.Verdict).values(
                id=v.id,
                artifact_id=v.artifact_id,
                state=v.state.value,
                risk_score=v.risk_score,
                confidence=v.confidence.value,
                recommended_response=v.recommended_response.value,
                applied_response=v.applied_response.value,
                explanation=v.explanation,
                engine_version=v.engine_version,
                ruleset_version=v.ruleset_version,
                created_at=v.created_at,
            )
        )
        for e in a.evidence:
            c.execute(
                insert(db.Evidence).values(
                    id=e.id,
                    artifact_id=v.artifact_id,
                    verdict_id=v.id,
                    kind=e.kind,
                    summary=e.summary,
                    sha256=e.sha256,
                )
            )
        for s in v.signals:
            detection_id = uuid.uuid4()
            c.execute(
                insert(db.Detection).values(
                    id=detection_id,
                    artifact_id=v.artifact_id,
                    verdict_id=v.id,
                    rule_id=s.rule_id,
                    category=s.category,
                    weight=s.weight,
                    description=s.description,
                    attack=s.attack,
                )
            )
            for evidence_id in s.evidence_ids:
                c.execute(
                    insert(db.DetectionEvidence).values(
                        detection_id=detection_id, evidence_id=evidence_id
                    )
                )
