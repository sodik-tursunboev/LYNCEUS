"""The sentence composer (DA5 phase 3, item 3): what Lynceus found, why, how sure, what to do next.

Pure and offline. Every fact comes from the arguments (state, score, confidence, recommended
response, the signals' rule ids); the wording comes from `phrases.toml` and adds none. No
probability is invented: "how sure" is the confidence tier the scorer already computed, stated as
it is. A rule id with no sentence falls back to a generic one, never an error.

`reword` lets a model (any callable; the real local model is not wired here) rephrase a sentence.
Its answer is used only if every number, domain-like token and rule or brand name in it occurs in
the sentence it was given; otherwise the deterministic text stands, unchanged. The model never
decides anything and cannot add a fact.
"""

import re
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from core.contracts import Confidence, ResponseAction, Signal, VerdictState

HERE = Path(__file__).parent
MAX_WHY = 2  # signs named in a flagged verdict: the extension shows at most 600 characters
_FLAGGED = (VerdictState.MALICIOUS, VerdictState.SUSPICIOUS)
_NUMBER = re.compile(r"\d+(?:[.,:]\d+)*")
_DOMAIN = re.compile(r"[\w-]+(?:\.[\w-]+)*\.[\w-]{2,}")  # also matches rule ids (url.typosquat)


@cache
def phrases() -> dict[str, Any]:
    return tomllib.loads((HERE / "phrases.toml").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Explanation:
    what: str
    why: str
    how_sure: str
    next: str

    @property
    def text(self) -> str:
        return " ".join(part for part in (self.what, self.why, self.how_sure, self.next) if part)


def _sentence(rule_id: str) -> str:
    rules: dict[str, str] = phrases()["rules"]
    return rules.get(rule_id) or phrases()["defaults"]["unknown_rule"].format(rule=rule_id[:60])


def compose(
    state: VerdictState,
    score: int | None,
    confidence: Confidence,
    response: ResponseAction,
    signals: Sequence[Signal],
    *,
    allowlisted: bool = False,
    caveat: str = "",
) -> Explanation:
    """`caveat`: the caller's own words on why an unknown is not safety (kept for UNKNOWN only)."""
    p = phrases()
    official = state is VerdictState.BENIGN and allowlisted
    base = "BENIGN_official" if official else state.value
    unknown = state is VerdictState.UNKNOWN
    weight: dict[str, float] = {}
    for s in signals:
        weight[s.rule_id] = max(weight.get(s.rule_id, 0.0), s.weight)
    shown = sorted(weight, key=lambda r: (-weight[r], r))[: 1 if unknown else MAX_WHY]

    what = p["what"].get("UNKNOWN_weak" if unknown and signals else base, p["what"]["other"])
    if shown and (unknown or state in _FLAGGED):
        why = " ".join(_sentence(r) for r in shown)
    else:
        why = p["why"].get(base, "")
    how = p["how_sure"].get(confidence.value if state in _FLAGGED else base, p["how_sure"]["other"])
    nxt = p["next"]
    nxt = nxt.get(f"{state.value}.{response.value}") or nxt.get(state.value) or nxt["other"]
    shown_score = "not given" if score is None else str(score)
    return Explanation(
        what=what.format(score=shown_score),
        why=why,
        how_sure=how,
        next=nxt.format(caveat=caveat.strip() or p["defaults"]["caveat"]),
    )


@cache
def _name_patterns() -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Brand and provider names. Long ones match in any case; two- and three-letter ones (DHL, UPS)
    only in capitals, so ordinary words are not mistaken for them."""
    from rules.intel.data import scoring as intel  # lazy: only reword needs the name lists
    from rules.page import page_brands

    names = {b.name for b in page_brands()} | {t for b in page_brands() for t in b.terms}
    names |= {k.split(".")[1] for k in intel()["weights"] if k.count(".") == 2}
    long = sorted({n.lower() for n in names if len(n) >= 4}, key=len, reverse=True)
    short = sorted({n for n in names if 2 <= len(n) <= 3 and n.isupper()})

    def pattern(words: list[str], flags: int) -> re.Pattern[str]:
        alt = "|".join(re.escape(w) for w in words)
        return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", flags)

    return pattern(long, 0), pattern(short, 0)


def claims(text: str) -> set[str]:
    """The checkable facts in a text: numbers, domain-like tokens (rule ids too), brand names."""
    low = text.lower()
    long_names, short_names = _name_patterns()
    found = {m.group() for rx in (_NUMBER, _DOMAIN, long_names) for m in rx.finditer(low)}
    return found | {m.group().lower() for m in short_names.finditer(text)}


def unsupported(text: str, facts: str) -> set[str]:
    """The claims in `text` that do not occur in `facts`."""
    return {c for c in claims(text) if not re.search(rf"(?<!\w){re.escape(c)}(?!\w)", facts, re.I)}


def reword(sentence: str, model: Callable[[str], str]) -> str:
    """The model's rewording of `sentence` if it adds no fact (and stays short); else `sentence`."""
    try:
        answer = model(sentence)
    except Exception:  # noqa: BLE001  (a broken model is never a reason to lose the explanation)
        return sentence
    said = " ".join(answer.split()) if isinstance(answer, str) else ""
    if not said or len(said) > 2 * len(sentence) or unsupported(said, sentence):
        return sentence
    return said
