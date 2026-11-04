"""Scoring (ADR-005). Positive prediction = SUSPICIOUS or MALICIOUS; BENIGN = negative prediction.

UNKNOWN and ERROR are neither: they are reported as abstain/error rates and never counted as
BENIGN. A positive sample the engine abstained on is still a miss in the headline recall.
"""

import math
from collections.abc import Iterable, Sequence

from pydantic import BaseModel

from core.contracts import VerdictState
from eval.corpus import Label

_POSITIVE = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)


class Counts(BaseModel):
    n: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn_benign: int = 0  # positive sample, engine said BENIGN
    abstain_pos: int = 0  # positive sample, engine said UNKNOWN
    abstain_neg: int = 0
    error_pos: int = 0  # positive sample, engine said ERROR
    error_neg: int = 0

    @property
    def fn(self) -> int:
        """Positives not flagged, whatever the reason."""
        return self.fn_benign + self.abstain_pos + self.error_pos

    @property
    def negatives(self) -> int:
        """Benign samples, whatever the engine said."""
        return self.tn + self.fp + self.abstain_neg + self.error_neg


class Interval(BaseModel):
    low: float
    high: float


class Rates(BaseModel):
    precision: float | None  # None = undefined (denominator 0)
    recall: float | None  # headline: abstain/error on a positive counts as a miss
    recall_answered: float | None  # recall over positives the engine actually answered
    f1: float | None  # from the headline recall
    flag_rate: float | None  # flagged benign samples; UNKNOWN counts as not flagged
    abstain_rate: float | None
    error_rate: float | None
    precision_ci: Interval | None
    recall_ci: Interval | None
    flag_rate_ci: Interval | None
    abstain_ci: Interval | None


def wilson(k: int, n: int, z: float = 1.959964) -> Interval | None:
    """Wilson score interval: honest at small n and at 0 or 1, where the normal one collapses."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return Interval(low=0.0 if k == 0 else centre - half, high=1.0 if k == n else centre + half)


def tally(pairs: Iterable[tuple[Label, VerdictState]]) -> Counts:
    c = Counts()
    for label, state in pairs:
        pos = label is Label.MALICIOUS
        c.n += 1
        if state in _POSITIVE:
            if pos:
                c.tp += 1
            else:
                c.fp += 1
        elif state is VerdictState.BENIGN:
            if pos:
                c.fn_benign += 1
            else:
                c.tn += 1
        elif state is VerdictState.UNKNOWN:
            if pos:
                c.abstain_pos += 1
            else:
                c.abstain_neg += 1
        elif pos:
            c.error_pos += 1
        else:
            c.error_neg += 1
    return c


def _div(a: int, b: int) -> float | None:
    return a / b if b else None


def rates(c: Counts) -> Rates:
    return Rates(
        precision=_div(c.tp, c.tp + c.fp),
        recall=_div(c.tp, c.tp + c.fn),
        recall_answered=_div(c.tp, c.tp + c.fn_benign),
        f1=_div(2 * c.tp, 2 * c.tp + c.fp + c.fn),
        flag_rate=_div(c.fp, c.negatives),
        abstain_rate=_div(c.abstain_pos + c.abstain_neg, c.n),
        error_rate=_div(c.error_pos + c.error_neg, c.n),
        precision_ci=wilson(c.tp, c.tp + c.fp),
        recall_ci=wilson(c.tp, c.tp + c.fn),
        flag_rate_ci=wilson(c.fp, c.negatives),
        abstain_ci=wilson(c.abstain_pos + c.abstain_neg, c.n),
    )


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile, q in (0, 100]."""
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(0, math.ceil(q / 100 * len(s)) - 1)]
