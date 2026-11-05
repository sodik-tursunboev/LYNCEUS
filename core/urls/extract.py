"""Find URLs in plain text (not HTML or email: that is M2). Linear time, hard caps.

Candidates are scheme-qualified (http, https, ftp, defanged hxxp) or start with `www.`. Returned
strings are raw candidates: pass each to `parse_url`, which refangs and normalises. The scanning
itself lives in `core/sandbox/guest/textscan.py`, shared with the sandbox worker.
"""

from typing import NamedTuple

from core.sandbox.guest.textscan import MAX_TEXT_LEN, MAX_URLS, find_urls
from core.urls.parse import MAX_URL_LEN

__all__ = ["MAX_TEXT_LEN", "MAX_URLS", "Extraction", "extract_urls"]


class Extraction(NamedTuple):
    urls: tuple[str, ...]  # unique, in order of appearance
    truncated: bool  # input or URL count hit a cap


def extract_urls(text: str, max_urls: int = MAX_URLS) -> Extraction:
    urls, truncated = find_urls(text, max_urls, MAX_URL_LEN)
    return Extraction(urls, truncated)
