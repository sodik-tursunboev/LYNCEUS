"""Find URLs in plain text (not HTML or email: that is M2). Linear time, hard caps.

Candidates are scheme-qualified (http, https, ftp, defanged hxxp) or start with `www.`. Returned
strings are raw candidates: pass each to `parse_url`, which refangs and normalises.
"""

import re
from typing import NamedTuple

from core.urls.parse import MAX_URL_LEN

MAX_TEXT_LEN = 1_000_000  # characters scanned; the rest is ignored and reported as truncated
MAX_URLS = 100

_CANDIDATE = re.compile(
    r"(?i)(?<!\w)(?:(?:https?|hxxps?|ftp)(?:://|\[:\]//|\[://\]|:\\\\)|www(?:\.|\[\.\]))"
    r"[^\s<>\"'`]+"
)
_STRIP = ".,;:!?*"
_CLOSER = {")": "(", "]": "[", "}": "{"}


class Extraction(NamedTuple):
    urls: tuple[str, ...]  # unique, in order of appearance
    truncated: bool  # input or URL count hit a cap


def _trim(candidate: str) -> str:
    """Drop trailing punctuation and unbalanced closing brackets, in one pass."""
    end = len(candidate)
    closers = {c: candidate.count(c) for c in _CLOSER}
    openers = {o: candidate.count(o) for o in _CLOSER.values()}
    while end:
        c = candidate[end - 1]
        if c in _STRIP:
            end -= 1
        elif c in _CLOSER and closers[c] > openers[_CLOSER[c]]:
            closers[c] -= 1
            end -= 1
        else:
            break
    return candidate[:end]


def extract_urls(text: str, max_urls: int = MAX_URLS) -> Extraction:
    truncated = len(text) > MAX_TEXT_LEN
    seen: dict[str, None] = {}
    for m in _CANDIDATE.finditer(text[:MAX_TEXT_LEN]):
        # One char over the cap, so parse_url still reports TOO_LONG for it.
        url = _trim(m.group(0)[: MAX_URL_LEN + 1])
        if len(url) > 1 and url not in seen:
            if len(seen) >= max_urls:
                truncated = True
                break
            seen[url] = None
    return Extraction(tuple(seen), truncated)
