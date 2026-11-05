"""Corpus manifest: JSONL, one CorpusEntry per line (see corpus/README.md).

Safety rules enforced at load time: malicious samples are synthetic and every host in them, the
real one and any hidden in an encoded redirect parameter, is unregisterable. Real public hosts are
allowed only for benign hard negatives, and are never fetched.
"""

import base64
import hashlib
import ipaddress
import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.urls.parse import ParsedUrl, parse_url


class Label(StrEnum):
    BENIGN = "benign"
    MALICIOUS = "malicious"


class Split(StrEnum):
    DEV = "dev"  # free to tune against
    HOLDOUT = "holdout"  # report only; never tune against
    RESERVE = "reserve"  # sealed: replaces the holdout after a holdout failure drives a fix


class Origin(StrEnum):
    SYNTHETIC = "synthetic"
    PUBLIC_REAL = "public_real"  # a real public URL string, benign only, never fetched


# RFC 2606 / 6761 reserved names and RFC 5737 / 3849 documentation addresses: unregisterable,
# so a seed can never point at a real party's host.
_SUFFIXES = (".test", ".invalid", ".example", ".localhost")
_EXACT = ("example.com", "example.org", "example.net")
_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_EMBEDDED = re.compile(r"(?i)(?:https?:)?(?://|\\\\)([^/\\\s?#&'\"<>()]+)")
_BASE64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_NO_HOST_SCHEMES = ("javascript:", "data:", "mailto:", "tel:")


def is_synthetic_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return (
            host.endswith(_SUFFIXES)
            or host in _EXACT
            or host.endswith(tuple("." + e for e in _EXACT))
        )
    return any(ip in net for net in _NETS)


def embedded_hosts(value: str) -> list[str]:
    """Hosts of URLs hidden in the value: percent-encoded (even twice) or base64 in a parameter."""
    text = unquote(unquote(value))
    tokens = _EMBEDDED.findall(text)
    for m in _BASE64.finditer(text):
        raw = m.group(0).replace("-", "+").replace("_", "/")
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("ascii")
        except ValueError:
            continue
        tokens += _EMBEDDED.findall(decoded)
    hosts = []
    for t in tokens:
        p = parse_url("http://" + t)
        hosts.append(p.host if isinstance(p, ParsedUrl) and p.host else t)
    return hosts


class CorpusEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Annotated[str, Field(min_length=1)]
    kind: Literal["url"] = "url"
    value: Annotated[str, Field(min_length=1)]
    label: Label
    category: Annotated[str, Field(min_length=1)]
    origin: Origin
    source: Annotated[str, Field(min_length=1)]  # provenance
    notes: str = ""
    split: Split

    @model_validator(mode="after")
    def _safe_to_keep(self) -> Self:
        if self.origin is Origin.PUBLIC_REAL:
            ok = self.label is Label.BENIGN and self.source.startswith("public:") and self.notes
            if not ok:
                raise ValueError(f"{self.id}: public_real is benign-only and needs source+notes")
            return self
        parsed = parse_url(self.value)
        if not isinstance(parsed, ParsedUrl):
            raise ValueError(f"{self.id}: seed does not parse ({parsed.reason})")
        if parsed.host is None and not self.value.lower().startswith(_NO_HOST_SCHEMES):
            raise ValueError(f"{self.id}: unexpected host-less seed")
        hosts = ([parsed.host] if parsed.host else []) + embedded_hosts(self.value)
        bad = [h for h in hosts if not is_synthetic_host(h)]
        if bad:
            raise ValueError(f"{self.id}: host {bad[0]!r} is not a reserved/synthetic name")
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


def split_hash(path: Path, split: Split) -> str:
    """sha256 of one split's raw manifest lines, in file order (pinned in corpus/pins.txt)."""
    h = hashlib.sha256()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line)["split"] == split.value:
            h.update(line.encode("utf-8") + b"\n")
    return h.hexdigest()


if __name__ == "__main__":  # python -m eval.corpus [manifest]: the lines for that corpus's pins.txt
    import sys

    manifest = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus/manifest.jsonl")
    for s in (Split.HOLDOUT, Split.RESERVE):
        print(s.value, split_hash(manifest, s))
