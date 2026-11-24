"""Popular registered domains (H1 B1): the top of the Tranco research list, kept on this machine.

A registered domain among the 100,000 most visited is an established site, not a fresh look-alike:
the look-alike rules that judge the registered name itself (typosquat, combosquat, brand in domain)
stay silent on it. That ends the false alarms on a brand's own country sites (google.no, amazon.ca)
and on domains a brand owns under other names (discordapp.com). It never makes anything BENIGN, and
the subdomain, homograph, path and page rules still apply, so `paypal.example.pages.dev` is judged
as before. Without the file (`python -m core.intel popular sync` not run yet) nothing changes.

Limits: Tranco is a research list (non-commercial use). A rank can be bought with fake traffic at
the low end, which is why only the top 100,000 is used; a long-lived phishing domain that reached
it would no longer be called a look-alike (the lists and the page rules still see it).
"""

import hashlib
import re
import threading
from array import array
from bisect import bisect_left
from collections.abc import Iterable
from pathlib import Path

FILE = "tranco-top.txt"
TOP = 100_000
RANKED_FILE = "tranco-ranked.bin"  # DA5: ranks 100,001 to 1,000,000, as sorted 8-byte hashes
RANKED_MAGIC = b"LYR1"
_DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_lock = threading.Lock()
_directory: Path | None = None
_cached: frozenset[str] | None = None
_ranked: array[int] | None = None


def configure(directory: Path | None) -> None:
    """Where the synced list lives (the core's data folder). Read once, on first use."""
    global _directory, _cached, _ranked
    with _lock:
        _directory, _cached, _ranked = directory, None, None


def use(domains: frozenset[str]) -> None:
    """Set the list directly: for tests and for evaluations that pin a dated copy."""
    global _cached
    with _lock:
        _cached = domains


def domains() -> frozenset[str]:
    global _cached
    with _lock:
        if _cached is None:
            _cached = _load(_directory / FILE) if _directory else frozenset()
        return _cached


def _load(path: Path) -> frozenset[str]:
    try:
        lines = path.read_text(encoding="ascii", errors="replace").splitlines()
    except OSError:
        return frozenset()
    return frozenset(s for line in lines if (s := line.strip().lower()) and not s.startswith("#"))


def is_popular(registered_domain: str | None) -> bool:
    return bool(registered_domain) and registered_domain in domains()


def _hash(domain: str) -> int:
    return int.from_bytes(
        hashlib.blake2b(domain.encode("ascii", "replace"), digest_size=8).digest(), "little"
    )


def ranked_bytes(domains_: Iterable[str]) -> bytes:
    """The file's content: a magic number and the sorted 8-byte hashes (7 MB for 900,000 names)."""
    table = array("Q", sorted({_hash(d) for d in domains_}))
    return RANKED_MAGIC + table.tobytes()


def use_ranked(domains_: Iterable[str] | None) -> None:
    """Set the ranked tier directly (tests, and evaluations that pin a dated copy)."""
    global _ranked
    with _lock:
        _ranked = array("Q", sorted({_hash(d) for d in domains_ or ()}))


def _load_ranked(path: Path) -> array[int]:
    out: array[int] = array("Q")
    try:
        raw = path.read_bytes()
    except OSError:
        return out
    if raw[:4] == RANKED_MAGIC and (len(raw) - 4) % out.itemsize == 0:
        out.frombytes(raw[4:])
    return out


def is_ranked(registered_domain: str | None) -> bool:
    """DA5: ranked 100,001 to 1,000,000 by Tranco: an ordinary established site, though not a top
    one. Used by the learned domain model only, never by the look-alike or any other rule. Without
    the file (`python -m core.intel popular sync` not run since DA5) nothing changes."""
    global _ranked
    if not registered_domain:
        return False
    with _lock:
        if _ranked is None:
            _ranked = _load_ranked(_directory / RANKED_FILE) if _directory else array("Q")
        table = _ranked
    h = _hash(registered_domain)
    i = bisect_left(table, h)
    return i < len(table) and table[i] == h


def ranked_from_csv(text: str, start: int = TOP, end: int = 1_000_000) -> list[str]:
    """`rank,domain` lines in rank order -> the well-formed domains ranked `start` to `end`."""
    out: list[str] = []
    seen = 0
    for line in text.splitlines():
        _, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if not _DOMAIN.match(domain):
            continue
        seen += 1
        if seen > end:
            break
        if seen > start:
            out.append(domain)
    return out


def top_from_csv(text: str, n: int = TOP) -> list[str]:
    """`rank,domain` lines in rank order (Tranco's format) -> the first `n` well-formed domains."""
    out: list[str] = []
    for line in text.splitlines():
        _, _, domain = line.partition(",")
        domain = domain.strip().lower()
        if _DOMAIN.match(domain):
            out.append(domain)
            if len(out) >= n:
                break
    return out
