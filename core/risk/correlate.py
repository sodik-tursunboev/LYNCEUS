"""Combine what the local rules found with what the providers said (M3, ADR-015).

The rule, from the owner's decision D3: each provider is its own category of evidence. One provider
listing the exact URL gives SUSPICIOUS with HIGH confidence (recommend WARN); two independent
providers, or one plus a strong local category, give MALICIOUS through the existing two-category
rule. Absence from a list is nothing. A provider that failed, timed out, was paused or was not asked
contributes nothing and is listed in the verdict, so a failure can neither raise nor lower a score.
With no provider results at all, the local analysis is returned untouched.
"""

import logging
from typing import Any

from core.contracts import (
    Confidence,
    Evidence,
    ProviderResult,
    ProviderStatus,
    Signal,
    VerdictState,
)
from core.detection.engine import UrlAnalysis, rescore
from core.intel.base import IntelOutcome, IntelResult
from rules.intel.data import merged_scoring, ruleset_version, scoring

log = logging.getLogger(__name__)
_FOUND = (VerdictState.MALICIOUS, VerdictState.SUSPICIOUS)


def _rule_id(r: IntelResult, cfg: dict[str, Any]) -> str | None:
    """Which configured weight a provider's finding earns, from its structured facts."""
    f, t = r.facts, cfg["thresholds"]
    if "listed" in f and "feed" in f:
        return f"intel.{f['feed']}.{f['listed']}"
    if isinstance(f.get("detections"), int):
        n = f["detections"]
        if n <= 0:
            return None
        return (
            "intel.virustotal.detections_many"
            if n >= t["vt_many"]
            else ("intel.virustotal.detections_few")
        )
    age = f.get("age_days")
    if isinstance(age, int) and age >= 0:
        for limit, band in ((t["age_week"], "week"), (t["age_month"], "month"),
                            (t["age_quarter"], "quarter")):  # fmt: skip
            if age < limit:
                return f"intel.domain_age.{band}"
    return None


def _signals(outcome: IntelOutcome, url_sha256: str) -> tuple[list[Signal], list[Evidence]]:
    cfg, weights = scoring(), scoring()["weights"]
    signals: list[Signal] = []
    evidence: list[Evidence] = []
    for r in outcome.results:
        res = r.result
        if res.status is not ProviderStatus.OK or res.state is None:
            continue
        rule_id = _rule_id(r, cfg)
        if rule_id is None:
            continue
        if rule_id not in weights:
            log.warning("intel finding %s has no configured weight and was ignored", rule_id)
            continue
        text = f"{res.provider}: {res.detail or res.state.value} ({res.provenance})"
        ev = Evidence(kind="intel", summary=text[:500], sha256=url_sha256)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=rule_id,
                category=rule_id.rsplit(".", 1)[0],
                weight=weights[rule_id],
                description=text[:500],
                evidence_ids=[ev.id],
            )
        )
    return signals, evidence


def provider_note(outcome: IntelOutcome) -> str:
    """One sentence on who answered and who did not, appended to the explanation."""
    results = outcome.results
    if not results and not outcome.skipped:
        return ""
    parts = []
    answered = [r for r in results if r.result.status is ProviderStatus.OK]
    if results:
        parts.append(f"{len(answered)} of {len(results)} providers answered")
    failed = [f"{r.result.provider} {r.result.status.value.lower()}" for r in results
              if r.result.status is not ProviderStatus.OK]  # fmt: skip
    if failed:
        parts.append("did not: " + ", ".join(failed))
    if outcome.skipped:
        parts.append("not asked: " + ", ".join(name for name, _ in outcome.skipped))
    quiet = [r for r in answered if r.result.state is VerdictState.UNKNOWN]
    if quiet:
        parts.append("a clean answer from a list proves nothing")
    return " Providers: " + "; ".join(parts) + "."


def correlate(local: UrlAnalysis, outcome: IntelOutcome) -> UrlAnalysis:
    if local.url is None or not outcome.results:
        return local  # nobody was asked: the verdict stays exactly the local one
    results: list[ProviderResult] = outcome.provider_results
    signals, evidence = _signals(outcome, local.url.url_sha256)
    exact = any(s.rule_id.endswith(".url") for s in signals)
    return rescore(
        local,
        signals,
        evidence,
        results,
        cfg=merged_scoring(),
        note=provider_note(outcome),
        version_suffix=f"intel.{ruleset_version()}",
        confidence_floor=Confidence.HIGH if exact else None,
    )
