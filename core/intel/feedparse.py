"""Parsers for downloaded feeds. Input is attacker-influenced bytes from a third party: every
parser is bounded, ignores what it does not understand, and yields URL strings (never fetched).

Formats below follow each provider's documentation as read on 2026-11-05; the URLhaus export layout
could not be read without an account and is *unverified* (the parser finds the url column by its
header and skips what it cannot place).
"""

import bz2
import csv
import io
import json
from collections.abc import Iterator

from core.intel.base import ProviderError

MAX_LINE = 8193  # one over the URL cap: longer entries are dropped by the URL parser anyway
MAX_ENTRIES = 1_000_000


def expand_bz2(data: bytes, limit: int) -> bytes:
    """Decompress at most `limit` bytes; more than that is a bomb or a broken feed."""
    out = bz2.BZ2Decompressor().decompress(data, limit + 1)
    if len(out) > limit:
        raise ProviderError("download expands beyond the limit")
    return out


def phishtank(data: bytes) -> Iterator[str]:
    """online-valid.json: a JSON list of objects with a `url` string."""
    try:
        items = json.loads(data)
    except (ValueError, RecursionError):
        raise ProviderError("feed is not valid JSON") from None
    if not isinstance(items, list):
        raise ProviderError("feed has an unexpected shape")
    for item in items[:MAX_ENTRIES]:
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and 0 < len(url) < MAX_LINE:
            yield url


def plain_lines(data: bytes) -> Iterator[str]:
    """OpenPhish feed.txt: one URL per line."""
    for count, raw in enumerate(data.splitlines()):
        if count >= MAX_ENTRIES:
            return
        line = raw.strip().decode("utf-8", "replace")
        if line and not line.startswith("#") and len(line) < MAX_LINE:
            yield line


def urlhaus_csv(data: bytes) -> Iterator[str]:
    """abuse.ch CSV export: '#' comment lines (the header is one of them), then rows with a `url`
    column; rows whose `url_status` says offline are skipped."""
    text = data.decode("utf-8", "replace")
    columns: list[str] = ["id", "dateadded", "url", "url_status"]
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            candidate = [c.strip().lower() for c in line.lstrip("# ").split(",")]
            if "url" in candidate:
                columns = candidate
        elif line.strip():
            body.append(line)
    url_at = columns.index("url")  # the documented layout when no header names it
    status_at = columns.index("url_status") if "url_status" in columns else None
    for count, row in enumerate(csv.reader(io.StringIO("\n".join(body)))):
        if count >= MAX_ENTRIES:
            return
        if len(row) <= url_at:
            continue
        if status_at is not None and len(row) > status_at and row[status_at].strip() == "offline":
            continue
        url = row[url_at].strip()
        if 0 < len(url) < MAX_LINE:
            yield url
