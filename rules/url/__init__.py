"""URL rule pack v1. A rule is a pure function: ParsedUrl in, evidence summary out (None = no hit).

Weights live in scoring.toml, lists in *.toml. Every rule needs a positive and a negative fixture in
corpus/rule_fixtures.toml; a test enforces it. Summaries are shown and logged: host facts only,
never the URL's path, query or userinfo values beyond what the rule matched on.
"""

from collections.abc import Callable
from dataclasses import dataclass

from core.urls.parse import ParsedUrl

SPEARPHISHING_LINK = "T1566.002"  # ATT&CK v20: Phishing: Spearphishing Link


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    attack: str
    check: Callable[[ParsedUrl], str | None]


RULES: list[Rule] = []


def rule(
    rule_id: str, category: str, attack: str = SPEARPHISHING_LINK
) -> Callable[[Callable[[ParsedUrl], str | None]], Callable[[ParsedUrl], str | None]]:
    def register(fn: Callable[[ParsedUrl], str | None]) -> Callable[[ParsedUrl], str | None]:
        RULES.append(Rule(rule_id, category, attack, fn))
        return fn

    return register


from rules.url import host, impersonation  # noqa: E402, F401  (imported to register their rules)
