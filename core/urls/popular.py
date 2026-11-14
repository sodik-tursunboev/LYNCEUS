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

import re
import threading
from pathlib import Path

FILE = "tranco-top.txt"
TOP = 100_000
_DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_lock = threading.Lock()
_directory: Path | None = None
_cached: frozenset[str] | None = None


def configure(directory: Path | None) -> None:
    """Where the synced list lives (the core's data folder). Read once, on first use."""
    global _directory, _cached
    with _lock:
        _directory, _cached = directory, None


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
