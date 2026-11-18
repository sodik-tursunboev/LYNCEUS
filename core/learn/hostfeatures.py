"""Features of a registered domain for the learned model (AI1 P1). Hashed, so the model is a flat
list of weights; every feature keeps its readable token so a verdict can say which parts pushed it.

Only the REGISTERED DOMAIN is read (`google.com` in `accounts.google.com`), never the subdomain or
the path. E1's legitimate hosts are bare domains while real browsing is full of subdomains, so a
model that read subdomains learned "a subdomain means phishing" and flagged 28% of the owner's
browsing (first run, docs/eval/learned-url.md). Subdomain tricks are the rules' job. Tokens:
character 3- to 5-grams of the registered label, the public suffix, and bucketed structure
(length, digits, hyphens, letter entropy, brand and keyword words, punycode).

DA1 (model 2): more of the label's shape, chosen on the calibration domains (phishing caught at 0.5%
of legitimate domains flagged: 48.1% to 50.2%): the share of vowels, the longest run of
consonants, how often letters and digits alternate, the number of hyphen-separated words, the
suffix's length, and the suffix together with the label's length and hyphen count (a long hyphenated
name means something different under .com than under .top).
"""

import math
import re
import zlib
from collections import Counter

from core.urls.parse import HostKind, ParsedUrl
from rules.url.data import brands, lists

BUCKETS = 1 << 18


def _bucket(value: int, edges: tuple[int, ...]) -> str:
    for edge in edges:
        if value <= edge:
            return f"<={edge}"
    return f">{edges[-1]}"


def _grams(prefix: str, text: str) -> list[str]:
    padded = f"^{text}$"
    return [
        f"{prefix}{padded[i : i + n]}"
        for n in (3, 4, 5)
        for i in range(max(0, len(padded) - n + 1))
    ]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def tokens(u: ParsedUrl) -> list[str]:
    """The readable features of one URL's registered domain."""
    if u.host_kind is not HostKind.DOMAIN or not u.registered_domain:
        return ["kind:ip" if u.host_kind is not HostKind.DOMAIN else "kind:no_registered_domain"]
    registered = u.registered_domain.lower()
    label = registered.split(".")[0]
    suffix = registered[len(label) + 1 :]
    found: list[str] = [
        f"suffix:{suffix}",
        f"label_len:{_bucket(len(label), (4, 6, 8, 10, 13, 16, 20, 30))}",
        f"label_digits:{_bucket(sum(c.isdigit() for c in label), (0, 1, 3))}",
        f"label_hyphens:{_bucket(label.count('-'), (0, 1, 2))}",
        f"label_entropy:{_bucket(int(_entropy(label) * 4), (8, 10, 12, 14))}",
    ]
    if label.startswith("xn--"):
        found.append("punycode")
    words = set(label.split("-"))
    if any(t in words or (len(t) >= 5 and t in label) for b in brands() for t in b.terms):
        found.append("brand_word")
    if any(k in label for k in lists()["keywords"]):
        found.append("keyword")
    return found + _shape(label, suffix, words) + _grams("l:", label)


_VOWELS = frozenset("aeiouy")
_CONSONANT_RUN = re.compile(r"[^aeiouy0-9-]+")


def _shape(label: str, suffix: str, words: set[str]) -> list[str]:
    """DA1 (model 2): more of the label's shape (see the module text)."""
    letters = [c for c in label if c.isalpha()]
    vowels = sum(c in _VOWELS for c in letters) / len(letters) if letters else 0.0
    run = max((len(m) for m in _CONSONANT_RUN.findall(label)), default=0)
    switches = sum(
        1 for a, b in zip(label, label[1:], strict=False)
        if a.isdigit() != b.isdigit() and a != "-" and b != "-"
    )  # fmt: skip
    return [
        f"vowels:{_bucket(int(vowels * 10), (2, 3, 4, 5))}",
        f"cons_run:{_bucket(run, (2, 3, 4, 5))}",
        f"switch:{_bucket(switches, (0, 1, 2, 4))}",
        f"parts:{_bucket(len(words), (1, 2, 3))}",
        f"suffix_len:{_bucket(len(suffix), (2, 3, 4, 6))}",
        f"suffix+len:{suffix}|{_bucket(len(label), (6, 10, 16))}",
        f"suffix+hyph:{suffix}|{min(label.count('-'), 2)}",
    ]


def index(token: str) -> int:
    return zlib.crc32(token.encode("utf-8")) % BUCKETS


def features(u: ParsedUrl) -> dict[int, str]:
    """Bucket -> one token that lands there (collisions keep the first, for explanations)."""
    out: dict[int, str] = {}
    for t in tokens(u):
        out.setdefault(index(t), t)
    return out
