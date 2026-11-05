"""Load the intelligence scoring data. Offline; nothing here touches the network."""

import hashlib
import tomllib
from functools import cache
from pathlib import Path
from typing import Any

from rules.url.data import scoring as url_scoring

HERE = Path(__file__).parent


@cache
def scoring() -> dict[str, Any]:
    return tomllib.loads((HERE / "scoring.toml").read_text(encoding="utf-8"))


@cache
def merged_scoring() -> dict[str, Any]:
    """The URL pack's thresholds and caps plus the intelligence categories' caps."""
    url = url_scoring()
    return {
        "thresholds": url["thresholds"],
        "category_caps": {**url["category_caps"], **scoring()["category_caps"]},
    }


@cache
def ruleset_version() -> str:
    digest = hashlib.sha256((HERE / "scoring.toml").read_bytes()).hexdigest()[:12]
    return f"{scoring()['ruleset']['version']}+{digest}"
