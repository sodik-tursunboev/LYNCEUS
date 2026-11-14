"""Add checked brain findings to a message or file verdict (AI1). The same scoring model as the
rules, with the `brain` category from the pack's scoring file; the result is never lower than the
verdict it started from, and an ERROR stays an ERROR."""

from collections.abc import Mapping
from typing import Any

from core.contracts import Evidence, Signal, Verdict, VerdictState
from core.risk.scoring import score

_RANK = {
    VerdictState.UNKNOWN: 0, VerdictState.BENIGN: 0, VerdictState.SUSPICIOUS: 1,
    VerdictState.MALICIOUS: 2, VerdictState.ERROR: 0,
}  # fmt: skip


def apply(
    verdict: Verdict,
    evidence: list[Evidence],
    signals: list[Signal],
    added: list[Evidence],
    cfg: Mapping[str, Any],
) -> tuple[Verdict, list[Evidence]]:
    if not signals or verdict.state is VerdictState.ERROR:
        return verdict, evidence
    every = [*verdict.signals, *signals]
    scored = score(every, False, cfg)
    state = scored.state if _RANK[scored.state] > _RANK[verdict.state] else verdict.state
    changed = state is not verdict.state
    risk = None if state is VerdictState.UNKNOWN else max(
        scored.risk_score or 0, verdict.risk_score or 0
    )  # fmt: skip
    note = " The local model added checked findings: " + "; ".join(s.description for s in signals)
    updated = Verdict.model_validate(
        {
            **verdict.model_dump(),
            "state": state,
            "risk_score": risk,
            "confidence": scored.confidence if changed else verdict.confidence,
            "signals": [s.model_dump() for s in every],
            "evidence_ids": [*verdict.evidence_ids, *(e.id for e in added)],
            "recommended_response": scored.recommended_response
            if changed
            else verdict.recommended_response,
            "explanation": (verdict.explanation + note)[:4000],
        }
    )
    return updated, [*evidence, *added]
