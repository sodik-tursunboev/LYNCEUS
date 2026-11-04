"""Corpus manifest: JSONL, one CorpusEntry per line. Synthetic hosts only (ADR-006)."""

import ipaddress
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Label(StrEnum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class Split(StrEnum):
    DEV = "dev"  # free to tune against
    HOLDOUT = "holdout"  # report only; never tune against


# RFC 2606 / 6761 reserved names and RFC 5737 / 3849 documentation addresses: unregisterable,
# so a seed can never point at a real party's host.
_SUFFIXES = (".test", ".invalid", ".example", ".localhost")
_EXACT = ("example.com", "example.org", "example.net")
_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def is_synthetic_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return (
            host.endswith(_SUFFIXES)
            or host in _EXACT
            or host.endswith(tuple("." + e for e in _EXACT))
        )
    return any(ip in net for net in _NETS)


class CorpusEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Annotated[str, Field(min_length=1)]
    kind: Literal["url"] = "url"
    value: Annotated[str, Field(min_length=1)]
    label: Label
    category: Annotated[str, Field(min_length=1)]
    source: Annotated[str, Field(min_length=1)]  # provenance
    notes: str = ""
    split: Split

    @model_validator(mode="after")
    def _synthetic_only(self) -> "CorpusEntry":
        host = urlsplit(self.value).hostname
        if not is_synthetic_host(host):
            raise ValueError(f"{self.id}: host {host!r} is not a reserved/synthetic name")
        return self


def load_manifest(path: Path) -> list[CorpusEntry]:
    entries = [
        CorpusEntry.model_validate(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ids = [e.id for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate ids in manifest")
    return entries
