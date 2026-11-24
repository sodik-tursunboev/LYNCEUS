"""Bands of a verdict and what a calibration run measured for them (DA5 phase 3, item 4).

A band is a score range ("score 45-59") or a state and confidence tier ("SUSPICIOUS LOW"). For each
one `eval.calibrate` measures two LIKELIHOODS, never a probability that a page is phishing: the
detection rate (the share of phishing samples that land in the band) and the false-alarm rate (the
share of legitimate samples that land in it). The evaluation sets are about half phishing and a
person's traffic is a tiny fraction, so "how often is a page in this band phishing" measured on
them would mean nothing; `posterior` turns the two rates into that number only at a prevalence you
state, as an illustration. The rates are in calibration.toml. Nothing here changes a verdict.
"""

import tomllib
from pathlib import Path
from typing import Any

PATH = Path(__file__).with_name("calibration.toml")
# 45 = SUSPICIOUS and 80 = MALICIOUS in scoring.toml, 95 = a "certain" rule's floor, 60 = between
_EDGES = (45, 60, 80, 95)
UNSCORED = "unscored"  # UNKNOWN and ERROR carry no score, and are never read as a low one


def score_band(risk: int | None) -> str:
    if risk is None:
        return UNSCORED
    lo = max((e for e in _EDGES if e <= risk), default=0)
    hi = min((e for e in _EDGES if e > risk), default=101) - 1
    return f"score {lo}-{hi}"


def tier_band(state: str, confidence: str) -> str:
    return f"{state} {confidence}"


def bands_of(state: str, risk: int | None, confidence: str) -> tuple[str, str]:
    """The score band and the state/confidence tier of one verdict."""
    return score_band(risk), tier_band(state, confidence)


def posterior(prevalence: float, detection: float, false_alarm: float) -> float:
    """P(phishing | band) at a STATED prevalence, from the band's two likelihoods (Bayes). An
    illustration, never a measurement: the prevalence is an assumption."""
    hit, miss = prevalence * detection, (1 - prevalence) * false_alarm
    return hit / (hit + miss) if hit + miss else 0.0


def load(path: Path = PATH) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)
