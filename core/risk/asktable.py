"""How loudly to tell the person about a verdict (DA5 phase 3, item 4). Pure and table-driven.

NOT WIRED: nothing in the agent, the extension or the API calls this in this version. It is the
table, its rules and its tests, ready to be chosen into the product.

Only the LOUDNESS changes. The verdict's state, score, confidence and recommended response are
never touched, and a quiet answer is never a statement that something is safe.

    loudness(state, tier, source, provider_complete, familiarity) -> Loudness

    interrupt  stops what you are doing (a block page, a modal) and asks for a decision
    ask_once   one targeted question, once per site or message ("Move this message out of the
               inbox?"), waiting for an answer; louder than a banner, softer than an interrupt
    banner     a visible notice that does not block
    log        recorded in the console history only

Tier is the verdict's confidence: LOW is one strong category of evidence, MEDIUM two, HIGH three or
a list match. A MALICIOUS verdict always has two (or a list match), so it is never LOW.
`provider_complete` is False when a provider that was asked did not answer (timeout, error, rate
limit, circuit open). `familiarity` is "unknown" for now: no per-site memory exists yet.

    state       source    LOW        MEDIUM     HIGH
    MALICIOUS   browser   banner     interrupt  interrupt
    MALICIOUS   download  banner     ask_once   interrupt
    MALICIOUS   mail      banner     ask_once   ask_once
    SUSPICIOUS  browser   banner     ask_once   ask_once
    SUSPICIOUS  download  log        banner     banner
    SUSPICIOUS  mail      log        banner     banner
    BENIGN      any       log        log        log
    UNKNOWN     any       log        log        log
    ERROR       browser   banner     banner     banner
    ERROR       download  banner     banner     banner
    ERROR       mail      log        log        log

An incomplete provider answer raises UNKNOWN and ERROR to at least a banner (a provider that did
not answer is never read as "nothing found"). Hard rules, enforced by tests/unit/test_ask_table.py:
a MALICIOUS verdict is never quieter than a banner, and in the browser it interrupts; UNKNOWN is
logged at least; automatic responses (`auto_may_apply`) never apply to mail or to SUSPICIOUS.
"""

from enum import StrEnum
from typing import Literal, get_args

from core.contracts import Confidence, VerdictState

Source = Literal["browser", "download", "mail"]
Familiarity = Literal["unknown"]
SOURCES: tuple[Source, ...] = get_args(Source)


class Loudness(StrEnum):
    INTERRUPT = "interrupt"
    BANNER = "banner"
    LOG = "log"
    ASK_ONCE = "ask_once"


RANK = {Loudness.LOG: 0, Loudness.BANNER: 1, Loudness.ASK_ONCE: 2, Loudness.INTERRUPT: 3}

_L, _B, _A, _I = Loudness.LOG, Loudness.BANNER, Loudness.ASK_ONCE, Loudness.INTERRUPT
_M, _S, _BE, _U, _E = (
    VerdictState.MALICIOUS,
    VerdictState.SUSPICIOUS,
    VerdictState.BENIGN,
    VerdictState.UNKNOWN,
    VerdictState.ERROR,
)
# (state, source) -> loudness for (LOW, MEDIUM, HIGH) confidence, when every provider answered
TABLE: dict[tuple[VerdictState, Source], tuple[Loudness, Loudness, Loudness]] = {
    (_M, "browser"): (_B, _I, _I), (_M, "download"): (_B, _A, _I), (_M, "mail"): (_B, _A, _A),
    (_S, "browser"): (_B, _A, _A), (_S, "download"): (_L, _B, _B), (_S, "mail"): (_L, _B, _B),
    (_BE, "browser"): (_L, _L, _L), (_BE, "download"): (_L, _L, _L), (_BE, "mail"): (_L, _L, _L),
    (_U, "browser"): (_L, _L, _L), (_U, "download"): (_L, _L, _L), (_U, "mail"): (_L, _L, _L),
    (_E, "browser"): (_B, _B, _B), (_E, "download"): (_B, _B, _B), (_E, "mail"): (_L, _L, _L),
}  # fmt: skip
# states whose answer rests on the providers having had their say: a silent provider is shown
_NEEDS_ANSWER = (_U, _E)
_TIERS = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def loudness(
    state: VerdictState,
    tier: Confidence,
    source: Source,
    provider_complete: bool,
    familiarity: Familiarity = "unknown",
) -> Loudness:
    # familiarity has one value so far; it is a parameter so that adding "familiar" later is a
    # change to this table, not to its callers
    chosen = TABLE[(state, source)][_TIERS.index(tier)]
    if not provider_complete and state in _NEEDS_ANSWER and RANK[chosen] < RANK[_B]:
        return _B
    return chosen


def auto_may_apply(state: VerdictState, source: Source) -> bool:
    """Whether an automatic response (ResponseMode "auto") may act without asking: only a file
    judged MALICIOUS. Never mail (quarantining a message needs its own, wider permission) and never
    SUSPICIOUS (a warning is not proof)."""
    return state is VerdictState.MALICIOUS and source == "download"
