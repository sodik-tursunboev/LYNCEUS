"""Load the rule pack's data files once. Offline; nothing here touches the network."""

import hashlib
import tomllib
import unicodedata
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
CONFUSABLES = HERE / "data" / "confusables.txt"
_HASHED = ("scoring.toml", "brands.toml", "lists.toml", "data/confusables.txt")


@dataclass(frozen=True)
class Brand:
    name: str
    terms: tuple[str, ...]
    domains: tuple[str, ...]
    fuzzy: bool


def _toml(name: str) -> dict[str, Any]:
    return tomllib.loads((HERE / name).read_text(encoding="utf-8"))


@cache
def scoring() -> dict[str, Any]:
    return _toml("scoring.toml")


@cache
def lists() -> dict[str, Any]:
    return _toml("lists.toml")


@cache
def brands() -> tuple[Brand, ...]:
    return tuple(
        Brand(b["name"], tuple(b["terms"]), tuple(b["domains"]), b.get("fuzzy", True))
        for b in _toml("brands.toml")["brands"]
    )


@cache
def official_domains() -> dict[str, str]:
    """Registered domain -> brand name."""
    return {d: b.name for b in brands() for d in b.domains}


@cache
def _confusables() -> dict[str, str]:
    table: dict[str, str] = {}
    for line in CONFUSABLES.read_text(encoding="utf-8-sig").splitlines():
        if not line or line.startswith("#"):
            continue
        source, target, *_ = (f.strip() for f in line.split(";"))
        table[chr(int(source, 16))] = "".join(chr(int(c, 16)) for c in target.split())
    return table


@cache
def skeleton(text: str) -> str:
    """UTS #39 skeleton, lowercased: two strings that look alike share one."""
    mapped = "".join(_confusables().get(c, c) for c in unicodedata.normalize("NFD", text))
    return unicodedata.normalize("NFD", mapped).lower()


@cache
def ruleset_version() -> str:
    """Semver from scoring.toml plus a hash of every data file, so any data change is visible."""
    h = hashlib.sha256()
    for name in _HASHED:
        h.update((HERE / name).read_bytes())
    return f"{scoring()['ruleset']['version']}+{h.hexdigest()[:12]}"
