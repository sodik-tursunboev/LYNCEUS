"""Public Suffix List lookup against the bundled snapshot (data/PROVENANCE.md). No runtime fetch."""

from functools import cache
from pathlib import Path
from typing import NamedTuple

import ada_url

DATA = Path(__file__).parent / "data" / "public_suffix_list.dat"
_PRIVATE_SECTION = "===BEGIN PRIVATE DOMAINS==="


class Match(NamedTuple):
    public_suffix: str
    registered_domain: str | None  # None when the host is itself a public suffix
    private: bool  # suffix is a multi-tenant host (github.io, ...), not a registry


class _Rules(NamedTuple):
    plain: dict[str, bool]  # rule text -> from the PRIVATE section?
    wildcard: dict[str, bool]  # "*.ck" is stored as "ck"
    exception: dict[str, bool]  # "!www.ck" is stored as "www.ck"


def _ascii(rule: str) -> str:
    """Rules may be written in Unicode; hosts reach us as punycode."""
    return ".".join(
        label if label.isascii() else bytes(ada_url.idna.encode(label)).decode("ascii")
        for label in rule.split(".")
    )


@cache
def _load() -> _Rules:
    plain: dict[str, bool] = {}
    wildcard: dict[str, bool] = {}
    exception: dict[str, bool] = {}
    private = False
    for line in DATA.read_text(encoding="utf-8").splitlines():
        if _PRIVATE_SECTION in line:
            private = True
            continue
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        table = plain
        if rule.startswith("!"):
            table, rule = exception, rule[1:]
        elif rule.startswith("*."):
            table, rule = wildcard, rule[2:]
        table[_ascii(rule)] = private
    return _Rules(plain, wildcard, exception)


def _result(labels: list[str], suffix_len: int, private: bool) -> Match:
    suffix = ".".join(labels[-suffix_len:])
    registered = ".".join(labels[-(suffix_len + 1) :]) if len(labels) > suffix_len else None
    return Match(suffix, registered, private)


def lookup(host: str) -> Match:
    """`host`: lowercase ASCII (punycode) domain name, no trailing dot, not an IP address.

    Implements the algorithm at publicsuffix.org/list: an exception rule always prevails,
    otherwise the rule with the most labels; no rule means the implicit rule `*` (last label).
    """
    rules = _load()
    labels = host.split(".")
    for i in range(len(labels)):
        tail = ".".join(labels[i:])
        if tail in rules.exception:
            return _result(labels, len(labels) - i - 1, rules.exception[tail])
    for i in range(len(labels)):  # longest candidate first, so the first hit is the longest rule
        n = len(labels) - i
        if n < 2:
            break
        tail = ".".join(labels[i:])
        if tail in rules.plain:
            return _result(labels, n, rules.plain[tail])
        parent = ".".join(labels[i + 1 :])
        if parent in rules.wildcard:
            return _result(labels, n, rules.wildcard[parent])
    # Single-label rules (com, uk, ...) and the implicit `*` rule both give: the last label.
    last = labels[-1]
    return _result(labels, 1, rules.plain.get(last, False))
