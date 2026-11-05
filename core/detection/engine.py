"""The deterministic URL engine: raw URL in, verdict and evidence out. Offline by construction."""

import hashlib
import logging
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from core.contracts import (
    Artifact,
    Confidence,
    Evidence,
    ProviderResult,
    ResponseAction,
    Signal,
    Verdict,
    VerdictState,
)
from core.risk.scoring import Scored, score
from core.urls.parse import HostKind, ParsedUrl, ParseFailure, UrlFlag, parse_url
from rules.url import RULES
from rules.url.data import lists, official_domains, ruleset_version, scoring

ENGINE_VERSION = "1.0.0"
_NOT_SAFE = "This is not evidence of safety: there are no reputation, age or page-content checks."
log = logging.getLogger(__name__)


class UrlReport(BaseModel):
    """What callers see: the API and the CLI print this shape."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    evidence: tuple[Evidence, ...]
    normalized_url: str | None
    flags: tuple[UrlFlag, ...]
    reason: str | None  # why the URL was not analysed: empty, too_long, unparseable, no_host, error


class UrlAnalysis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    input_sha256: str
    url: ParsedUrl | None  # None when the input could not be parsed
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    reason: str | None = None

    def report(self) -> UrlReport:
        return UrlReport(
            verdict=self.verdict,
            evidence=self.evidence,
            normalized_url=self.url.normalized if self.url else None,
            flags=self.url.flags if self.url else (),
            reason=self.reason,
        )


def _allowlisted(u: ParsedUrl) -> bool:
    """An official host, and not one where anyone can publish content (ADR-013)."""
    if u.scheme not in ("http", "https") or u.host_kind is not HostKind.DOMAIN or not u.host:
        return False
    if u.private_suffix or u.registered_domain not in official_domains():
        return False
    return not any(u.host == h or u.host.endswith("." + h) for h in lists()["shared_hosts"])


def _verdict(
    artifact_id: UUID, scored: Scored, signals: list[Signal], evidence: list[Evidence], why: str
) -> Verdict:
    return Verdict(
        artifact_id=artifact_id,
        state=scored.state,
        risk_score=scored.risk_score,
        confidence=scored.confidence,
        signals=signals,
        evidence_ids=[e.id for e in evidence],
        provider_results=[],
        recommended_response=scored.recommended_response,
        applied_response=ResponseAction.NONE,
        explanation=why,
        engine_version=ENGINE_VERSION,
        ruleset_version=ruleset_version(),
    )


def _explain(scored: Scored, signals: list[Signal], allowlisted: bool) -> str:
    if scored.state is VerdictState.UNKNOWN:
        if signals:
            return f"{len(signals)} weak signal(s), not enough to call it. {_NOT_SAFE}"
        return f"No rule fired. {_NOT_SAFE}"
    if scored.state is VerdictState.BENIGN:
        return "Official domain of a known brand." if allowlisted else "No risk found."
    names = ", ".join(s.rule_id for s in signals)
    return f"Score {scored.risk_score} from: {names}."


def _unscored(
    artifact_id: UUID, digest: str, state: VerdictState, why: str, reason: str
) -> UrlAnalysis:
    scored = Scored(state, None, Confidence.LOW, ResponseAction.NONE)
    verdict = _verdict(artifact_id, scored, [], [], why)
    return UrlAnalysis(input_sha256=digest, url=None, verdict=verdict, evidence=(), reason=reason)


def _rules(u: ParsedUrl) -> tuple[list[Signal], list[Evidence]]:
    weights = scoring()["weights"]
    signals, evidence = [], []
    for r in sorted(RULES, key=lambda r: r.id):
        summary = r.check(u)
        if summary is None:
            continue
        ev = Evidence(kind="url_rule", summary=summary, sha256=u.url_sha256)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=r.id,
                category=r.category,
                weight=weights[r.id],
                description=summary,
                evidence_ids=[ev.id],
                attack=r.attack,
            )
        )
    return signals, evidence


def analyze_url(raw: str, artifact_id: UUID | None = None) -> UrlAnalysis:
    aid = artifact_id or uuid4()
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()
    try:
        parsed = parse_url(raw)
        if isinstance(parsed, ParseFailure):
            why = f"Not analysed ({parsed.reason.value}): {parsed.detail}. {_NOT_SAFE}"
            return _unscored(aid, digest, VerdictState.UNKNOWN, why, parsed.reason.value.lower())
        signals, evidence = _rules(parsed)
        if parsed.has(UrlFlag.REFANGED):
            note = "the input was defanged; it was restored before analysis"
            evidence.append(Evidence(kind="input_note", summary=note, sha256=digest))
        allowlisted = _allowlisted(parsed)
        scored = score(signals, allowlisted, scoring())
        why = _explain(scored, signals, allowlisted)
        verdict = _verdict(aid, scored, signals, evidence, why)
        return UrlAnalysis(
            input_sha256=digest, url=parsed, verdict=verdict, evidence=tuple(evidence)
        )
    except Exception:  # never let a bug read as "no verdict": ERROR is an explicit state
        log.exception("url analysis failed")
        why = f"Analysis failed. {_NOT_SAFE}"
        return _unscored(aid, digest, VerdictState.ERROR, why, "error")


_CONFIDENCE_ORDER = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def rescore(
    a: UrlAnalysis,
    signals: list[Signal],
    evidence: list[Evidence],
    provider_results: list[ProviderResult],
    *,
    cfg: Mapping[str, Any],
    note: str,
    version_suffix: str,
    confidence_floor: Confidence | None = None,
) -> UrlAnalysis:
    """The same analysis with intelligence added: more signals, the providers' results, and a
    verdict scored again over all of them. Local signals are kept exactly as they were."""
    if a.url is None:
        return a
    all_signals = [*a.verdict.signals, *signals]
    all_evidence = [*a.evidence, *evidence]
    allow = _allowlisted(a.url)
    scored = score(all_signals, allow, cfg)
    if (
        confidence_floor is not None
        and scored.state in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
        and _CONFIDENCE_ORDER.index(scored.confidence) < _CONFIDENCE_ORDER.index(confidence_floor)
    ):
        scored = scored._replace(confidence=confidence_floor)
    old = a.verdict
    verdict = Verdict(
        artifact_id=old.artifact_id,
        state=scored.state,
        risk_score=scored.risk_score,
        confidence=scored.confidence,
        signals=all_signals,
        evidence_ids=[e.id for e in all_evidence],
        provider_results=provider_results,
        recommended_response=scored.recommended_response,
        applied_response=ResponseAction.NONE,
        explanation=_explain(scored, all_signals, allow) + note,
        engine_version=f"{old.engine_version}+intel",
        ruleset_version=f"{old.ruleset_version}+{version_suffix}",
    )
    return a.model_copy(update={"verdict": verdict, "evidence": tuple(all_evidence)})


def analyze(artifact: Artifact) -> Verdict:
    return analyze_url(artifact.ref, artifact.id).verdict
