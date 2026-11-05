"""Find URL candidates in plain text. Standard library only and linear time.

Shared on purpose: the sandbox worker and the host (`core.urls.extract`) use this one copy, so the
two can never disagree about what counts as a URL in text.
"""

import re

MAX_TEXT_LEN = 1_000_000  # characters scanned; the rest is ignored and reported as truncated
MAX_URLS = 100
DEFAULT_URL_CHARS = 8192

_CANDIDATE = re.compile(
    r"(?i)(?<!\w)(?:(?:https?|hxxps?|ftp)(?:://|\[:\]//|\[://\]|:\\\\)|www(?:\.|\[\.\]))"
    r"[^\s<>\"'`]+"
)
_STRIP = ".,;:!?*"
_CLOSER = {")": "(", "]": "[", "}": "{"}


def trim(candidate: str) -> str:
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


def find_urls(
    text: str, max_urls: int = MAX_URLS, max_url_chars: int = DEFAULT_URL_CHARS
) -> tuple[tuple[str, ...], bool]:
    """(unique candidates in order of appearance, whether a cap cut the scan short)."""
    truncated = len(text) > MAX_TEXT_LEN
    seen: dict[str, None] = {}
    for m in _CANDIDATE.finditer(text[:MAX_TEXT_LEN]):
        # One char over the cap, so the host's parser still reports it as too long.
        url = trim(m.group(0)[: max_url_chars + 1])
        if len(url) > 1 and url not in seen:
            if len(seen) >= max_urls:
                truncated = True
                break
            seen[url] = None
    return tuple(seen), truncated
