"""Rules about hosts pretending to be a brand: homographs, typos, combosquats, subdomain tricks.

All of them stay silent on a brand's official registered domain.
"""

import re
import unicodedata
from collections.abc import Iterator

from core.urls.parse import HostKind, ParsedUrl
from rules.url import rule
from rules.url.data import Brand, brands, lists, official_domains, skeleton

_MIN_FUZZY = 5  # shorter terms match exactly: everything is one edit from "ups"
_CJK = {"CJK", "HIRAGANA", "KATAKANA", "HANGUL"}


def _candidate(u: ParsedUrl) -> bool:
    if u.host_kind is not HostKind.DOMAIN or u.registered_domain is None:
        return False
    return u.registered_domain not in official_domains()


def _label(u: ParsedUrl) -> str:
    """The registered label: `paypal-login` in login.paypal-login.co.uk."""
    return (u.registered_domain or "").split(".")[0]


def _unicode_labels(u: ParsedUrl) -> list[str]:
    return (u.host_unicode or "").split(".")


def _terms() -> Iterator[tuple[Brand, str]]:
    return ((b, t) for b in brands() for t in b.terms)


def _distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein (adjacent swaps count once), early exit above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    before: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        row = [i]
        for j, cb in enumerate(b, 1):
            cost = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cost = min(cost, before[j - 2] + 1)
            row.append(cost)
        before, prev = prev, row
    return prev[-1]


def _collapse(text: str) -> str:
    return re.sub(r"(.)\1+", r"\1", text)


def _has_keyword(text: str) -> str | None:
    return next((k for k in lists()["keywords"] if k in text), None)


@rule("url.homograph_brand", "impersonation")
def homograph_brand(u: ParsedUrl) -> str | None:
    if not _candidate(u):
        return None
    for label in _unicode_labels(u):
        if label.isascii():
            continue
        shape = skeleton(label)
        for b, t in _terms():
            if shape == skeleton(t):
                return f"host label is a lookalike of {b.name} in other alphabets ({u.host})"
    return None


def _script(ch: str) -> str | None:
    # ponytail: script from the Unicode name, not Scripts.txt. Good for Latin vs Cyrillic/Greek;
    # bundle Scripts.txt if a rarer script pair ever matters.
    if not ch.isalpha():
        return None
    word = unicodedata.name(ch, "").split(" ")[0]
    return "CJK" if word in _CJK else word


@rule("url.mixed_script", "impersonation")
def mixed_script(u: ParsedUrl) -> str | None:
    if not _candidate(u):
        return None
    for label in _unicode_labels(u):
        scripts = sorted({s for s in map(_script, label) if s})
        if len(scripts) > 1:
            return f"one host label mixes alphabets: {', '.join(scripts)}"
    return None


@rule("url.typosquat", "impersonation")
def typosquat(u: ParsedUrl) -> str | None:
    if not _candidate(u):
        return None
    label = _label(u)
    if label.startswith("xn--") or label in lists()["not_typos"]:
        return None
    plain, shape, single = label.replace("-", ""), skeleton(label), _collapse(label)
    for b, t in _terms():
        if label == t or plain == t.replace("-", ""):
            return f"{b.name}'s name on a domain it does not own ({u.registered_domain})"
        if shape == skeleton(t) or (len(t) >= 3 and single == _collapse(t)):
            return f"{b.name} lookalike ({u.registered_domain})"
        if b.fuzzy and len(t) >= _MIN_FUZZY:
            limit = 2 if len(t) >= 9 else 1
            if _distance(label, t, limit) <= limit:
                return f"{b.name} misspelling ({u.registered_domain})"
    return None


def _brand_in_label(label: str) -> tuple[Brand, str] | None:
    tokens = set(re.split(r"[-_]", label))
    for b, t in _terms():
        if t in tokens or (len(t) >= _MIN_FUZZY and t in label):
            return b, t
        if len(t) >= 3 and label.startswith(t) and label[len(t) :] in lists()["keywords"]:
            return b, t
    return None


@rule("url.combosquat", "impersonation")
def combosquat(u: ParsedUrl) -> str | None:
    if not _candidate(u):
        return None
    label = _label(u)
    found = _brand_in_label(label)
    if found is None or label == found[1]:
        return None
    keyword = _has_keyword(label.replace(found[1], ""))
    if keyword:
        return f"{found[0].name}'s name plus '{keyword}' on {u.registered_domain}"
    return None


@rule("url.brand_in_domain", "impersonation")
def brand_in_domain(u: ParsedUrl) -> str | None:
    """Weak on purpose: fan sites and reviews name brands too."""
    if not _candidate(u):
        return None
    label = _label(u)
    found = _brand_in_label(label)
    if found is None or label == found[1] or _has_keyword(label.replace(found[1], "")):
        return None
    return f"{found[0].name}'s name inside {u.registered_domain}"


@rule("url.brand_in_subdomain", "impersonation")
def brand_in_subdomain(u: ParsedUrl) -> str | None:
    if not _candidate(u) or not u.subdomain:
        return None
    wrapped = f".{u.subdomain}."
    for d in official_domains():  # also catches the domain glued to a word: paypal.com-login
        if f".{d}." in wrapped or f".{d}-" in wrapped:
            return f"{d} appears as a subdomain of {u.registered_domain}"
    labels = set(u.subdomain.split("."))
    for b, t in _terms():
        if t in labels:
            return f"{b.name}'s name appears as a subdomain of {u.registered_domain}"
    return None
