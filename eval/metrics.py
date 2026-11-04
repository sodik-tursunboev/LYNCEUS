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


class Rates(BaseModel):
    precision: float | None  # None = undefined (denominator 0)
    recall: float | None  # headline: abstain/error on a positive counts as a miss
    recall_answered: float | None  # recall over positives the engine actually answered
    f1: float | None  # from the headline recall
    abstain_rate: float | None
    error_rate: float | None


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
        abstain_rate=_div(c.abstain_pos + c.abstain_neg, c.n),
        error_rate=_div(c.error_pos + c.error_neg, c.n),
    )


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile, q in (0, 100]."""
    if not values:
        return 0.0
    s = sorted(values)
    return s[max(0, math.ceil(q / 100 * len(s)) - 1)]
