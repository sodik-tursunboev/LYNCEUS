"""Signals to a state and a score (ADR-013). Pure; every number comes from config.

Score: noisy-OR inside each category, capped, then noisy-OR across categories. Correlated signals
therefore cannot add up to certainty on their own. MALICIOUS also needs independent evidence.
"""

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from core.contracts import Confidence, ResponseAction, Signal, VerdictState

_RESPONSE = {
    VerdictState.MALICIOUS: ResponseAction.BLOCK,
    VerdictState.SUSPICIOUS: ResponseAction.WARN,
}
_CONFIDENCE = {0: Confidence.LOW, 1: Confidence.LOW, 2: Confidence.MEDIUM}


class Scored(NamedTuple):
    state: VerdictState
    risk_score: int | None
    confidence: Confidence
    recommended_response: ResponseAction


def _noisy_or(weights: Sequence[float]) -> float:
    return 1 - math.prod(1 - w for w in sorted(weights))


def score(signals: Sequence[Signal], allowlisted: bool, cfg: Mapping[str, Any]) -> Scored:
    t, caps = cfg["thresholds"], cfg["category_caps"]
    if not signals:
        if allowlisted:
            return Scored(VerdictState.BENIGN, 0, Confidence.HIGH, ResponseAction.NONE)
        return Scored(VerdictState.UNKNOWN, None, Confidence.LOW, ResponseAction.NONE)

    by_category: dict[str, list[float]] = defaultdict(list)
    for s in signals:
        by_category[s.category].append(s.weight)
    capped = [min(_noisy_or(ws), caps.get(c, 1.0)) for c, ws in sorted(by_category.items())]
    risk = round(100 * _noisy_or(capped))
    strong = sum(max(ws) >= t["high_weight"] for ws in by_category.values())
    confidence = _CONFIDENCE.get(strong, Confidence.HIGH)

    if risk >= t["malicious"] and strong >= t["min_categories"]:
        state = VerdictState.MALICIOUS
    elif risk >= t["suspicious"]:
        state = VerdictState.SUSPICIOUS
    elif allowlisted:
        return Scored(VerdictState.BENIGN, risk, Confidence.MEDIUM, ResponseAction.NONE)
    else:  # weak signals are not proof of anything, in either direction
        return Scored(VerdictState.UNKNOWN, None, Confidence.LOW, ResponseAction.NONE)
    return Scored(state, risk, confidence, _RESPONSE[state])
