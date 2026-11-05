"""Load the message rule pack's data once. Offline."""

import hashlib
import tomllib
import unicodedata
from functools import cache
from pathlib import Path
from typing import Any

from rules.url import data as url_data

HERE = Path(__file__).parent


@cache
def scoring() -> dict[str, Any]:
    return tomllib.loads((HERE / "scoring.toml").read_text(encoding="utf-8"))


@cache
def lists() -> dict[str, Any]:
    return tomllib.loads((HERE / "lists.toml").read_text(encoding="utf-8"))


@cache
def ruleset_version() -> str:
    """Semver, plus a hash of this pack's data and the URL pack's version (links depend on it)."""
    h = hashlib.sha256()
    for name in ("scoring.toml", "lists.toml"):
        h.update((HERE / name).read_bytes())
    h.update(url_data.ruleset_version().encode())
    return f"{scoring()['ruleset']['version']}+{h.hexdigest()[:12]}"


def plain(text: str) -> str:
    """Lowercase, accents and Polish letters flattened, spaces collapsed: for phrase matching."""
    text = text.lower().replace("\u0142", "l")
    text = "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")
    return " ".join(text.split())
