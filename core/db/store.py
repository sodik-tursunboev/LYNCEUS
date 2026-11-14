"""Persist an analysis (M1 decision D2, kept in M2): hashes, hosts, verdict, signals, evidence.

No URL text and no message text is stored: `artifacts.ref` is a hash reference, `extracted_urls.url`
stays NULL, and evidence summaries name hosts, types and counts only. Every text that can name a
site is sealed with DPAPI and looked up by a keyed hash (ADR-007, H1 A8, core/db/hosts.py). A
whole analysis lands in one transaction or not at all.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy import Connection, Engine, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from core.contracts import ArtifactKind, EventSource, Evidence, Verdict
from core.db import hosts
from core.db import models as db
from core.detection.engine import UrlAnalysis
from core.email.engine import EmailAnalysis, ExtractedRef
from core.files.engine import FileAnalysis

_MAX_HOST = 253  # longest DNS name, and the column size; longer hosts are hostile input


def _domain_id(c: Connection, host: str, registered: str | None) -> uuid.UUID:
    """By the host's keyed hash: the name itself is stored only sealed (ADR-007, H1 A8)."""
    key = hosts.tag(host)
    found = c.scalar(select(db.Domain.id).where(db.Domain.name == key))
    if found is None:
        new = uuid.uuid4()
        try:
            with c.begin_nested():
                c.execute(
                    insert(db.Domain).values(
                        id=new, name=key, sealed_name=hosts.seal(host),
                        registered_domain=hosts.tag(registered),
                    )
                )  # fmt: skip
            return new
        except IntegrityError:  # another writer added it first
            found = c.scalar(select(db.Domain.id).where(db.Domain.name == key))
            if found is None:
                raise
    c.execute(update(db.Domain).where(db.Domain.id == found).values(last_seen_at=func.now()))
    return found


def _write(
    engine: Engine,
    v: Verdict,
    evidence: Sequence[Evidence],
    kind: ArtifactKind,
    digest: str,
    host: str | None,
    source: EventSource,
    refs: Sequence[ExtractedRef] = (),
) -> None:
    event_id = uuid.uuid4()
    kept = host if host and len(host) <= _MAX_HOST else None
    with engine.begin() as c:
        c.execute(
            insert(db.Event).values(id=event_id, source=source.value, observed_at=v.created_at)
        )
        c.execute(
            insert(db.Artifact).values(
                id=v.artifact_id,
                event_id=event_id,
                kind=kind.value,
                sha256=digest,
                ref=f"sha256:{digest}",
                host=hosts.seal(kept),
                host_tag=hosts.tag(kept),
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
                explanation=hosts.seal(v.explanation),  # names hosts: sealed (ADR-007)
                engine_version=v.engine_version,
                ruleset_version=v.ruleset_version,
                created_at=v.created_at,
            )
        )
        for e in evidence:
            c.execute(
                insert(db.Evidence).values(
                    id=e.id,
                    artifact_id=v.artifact_id,
                    verdict_id=v.id,
                    kind=e.kind,
                    summary=hosts.seal(e.summary),
                    sha256=e.sha256,
                )
            )
        for r in v.provider_results:
            c.execute(
                insert(db.ProviderResult).values(
                    id=uuid.uuid4(),
                    artifact_id=v.artifact_id,
                    provider=r.provider,
                    status=r.status.value,
                    state=r.state.value if r.state else None,
                    queried_at=r.queried_at,
                    latency_ms=r.latency_ms,
                    provenance=r.provenance,
                    detail=r.detail,
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
                    description=hosts.seal(s.description),
                    attack=s.attack,
                )
            )
            for evidence_id in s.evidence_ids:
                c.execute(
                    insert(db.DetectionEvidence).values(
                        detection_id=detection_id, evidence_id=evidence_id
                    )
                )
        for ref in refs:
            usable = ref.host is not None and len(ref.host) <= _MAX_HOST
            domain = _domain_id(c, ref.host, ref.registered_domain) if usable and ref.host else None
            c.execute(
                insert(db.ExtractedUrl).values(
                    id=uuid.uuid4(),
                    artifact_id=v.artifact_id,
                    domain_id=domain,
                    url=None,
                    url_sha256=ref.url_sha256,
                    position=ref.position,
                )
            )


def save_analysis(engine: Engine, a: UrlAnalysis, source: EventSource) -> None:
    digest = a.url.url_sha256 if a.url else a.input_sha256
    host = a.url.host if a.url else None
    _write(engine, a.verdict, a.evidence, ArtifactKind.URL, digest, host, source)


def save_file_analysis(engine: Engine, a: FileAnalysis, source: EventSource) -> None:
    r = a.report
    _write(
        engine, r.verdict, r.evidence, ArtifactKind.FILE, a.sha256, a.origin_host, source, a.urls
    )


def save_email_analysis(engine: Engine, a: EmailAnalysis, source: EventSource) -> None:
    r = a.report
    _write(engine, r.verdict, r.evidence, ArtifactKind.EMAIL, a.input_sha256, None, source, a.urls)
