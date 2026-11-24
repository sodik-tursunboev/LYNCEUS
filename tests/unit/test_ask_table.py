"""The ask table (core/risk/asktable.py): its hard rules hold for every input, not just a sample."""

from itertools import product

from core.contracts import Confidence, VerdictState
from core.risk.asktable import (
    RANK,
    SOURCES,
    TABLE,
    Loudness,
    auto_may_apply,
    loudness,
)

TIERS = tuple(Confidence)
STATES = tuple(VerdictState)


def test_a_two_category_malicious_is_never_quieted() -> None:
    # MALICIOUS needs two independent strong categories, so its confidence is MEDIUM or HIGH
    for source, tier, complete in product(
        SOURCES, (Confidence.MEDIUM, Confidence.HIGH), (True, False)
    ):
        got = loudness(VerdictState.MALICIOUS, tier, source, complete)
        assert RANK[got] >= RANK[Loudness.BANNER], (source, tier, complete, got)
        if source == "browser":
            assert got is Loudness.INTERRUPT
    # and even a (never produced) LOW-confidence MALICIOUS is not silent
    for source, complete in product(SOURCES, (True, False)):
        assert RANK[loudness(VerdictState.MALICIOUS, Confidence.LOW, source, complete)] >= 1


def test_auto_never_touches_mail_or_suspicious() -> None:
    for state, source in product(STATES, SOURCES):
        allowed = auto_may_apply(state, source)
        if source == "mail" or state is VerdictState.SUSPICIOUS:
            assert not allowed, (state, source)
    # what auto may do is exactly one thing: a file judged MALICIOUS
    assert [(s, x) for s, x in product(STATES, SOURCES) if auto_may_apply(s, x)] == [
        (VerdictState.MALICIOUS, "download")
    ]


def test_the_table_covers_every_state_and_source() -> None:
    assert set(TABLE) == set(product(STATES, SOURCES))
    for state, tier, source, complete in product(STATES, TIERS, SOURCES, (True, False)):
        got = loudness(state, tier, source, complete, "unknown")
        assert isinstance(got, Loudness)
        if state is VerdictState.UNKNOWN:
            # never silent safety: recorded at least, and shown when a provider did not answer
            assert RANK[got] >= RANK[Loudness.LOG]
            assert complete or RANK[got] >= RANK[Loudness.BANNER], (source, tier)
        if state is VerdictState.ERROR and not complete:
            assert RANK[got] >= RANK[Loudness.BANNER]
