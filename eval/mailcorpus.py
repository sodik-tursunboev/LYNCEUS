"""Message corpus: corpus/mail/manifest.jsonl plus one .eml per entry (see corpus/README.md).

The files are synthetic and authored here, so the checks below parse them in-process; hostile mail
only ever goes through the sandbox. Safety rules, enforced at load time: each file matches its
recorded hash, malicious samples are synthetic, and every host a reader or mail client could reach
in a synthetic sample is unregisterable. Real official hosts are allowed in benign `public_real`
samples, and as *displayed text* in malicious ones (that is the attack being modelled).
"""

import email
import email.policy
import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from eval.corpus import Label, Origin, Split, is_synthetic_host
from rules.url.data import official_domains

MAX_FILE_BYTES = 1024 * 1024
_HOST = re.compile(r"(?i)(?:https?://|//)([a-z0-9._\-]+)")
_DESTINATION = re.compile(
    r"""(?i)\b(?:href|src|action)\s*=\s*["']?\s*(?:https?:)?//([a-z0-9._\-]+)"""
)
_PLAIN_URL = re.compile(r"(?i)\bhttps?://([a-z0-9._\-]+)")
_ADDRESS_DOMAIN = re.compile(r"(?i)[\w.+\-]+@([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)")
_TAGS = re.compile(r"<[^>]*>")


class MailEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Annotated[str, Field(min_length=1)]
    file: Annotated[str, Field(pattern=r"^[A-Za-z0-9_\-]+\.eml$")]
    file_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    label: Label
    category: Annotated[str, Field(min_length=1)]
    origin: Origin
    source: Annotated[str, Field(min_length=1)]
    notes: str = ""
    split: Split

    @model_validator(mode="after")
    def _origin_rules(self) -> Self:
        if self.origin is Origin.PUBLIC_REAL and self.label is not Label.BENIGN:
            raise ValueError(f"{self.id}: real host names are for benign messages only")
        if self.origin is Origin.PUBLIC_REAL and not self.source.startswith("public:"):
            raise ValueError(f"{self.id}: public_real needs a 'public:' source")
        return self


def _texts(raw: bytes) -> tuple[str, list[tuple[bool, str]]]:
    """(header text, [(is_html, decoded text)] for every text part and named attachment)."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    headers = "\n".join(str(v) for _, v in msg.items())
    parts: list[tuple[bool, str]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True)
        if isinstance(data, bytes) and (
            part.get_content_maintype() == "text" or part.get_filename()
        ):
            ctype = part.get_content_type()
            sniff = data[:200].lower()
            html = ctype in ("text/html", "image/svg+xml") or b"<html" in sniff or b"<form" in sniff
            parts.append((html, data.decode("utf-8", "replace")))
    return headers, parts


def _official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in official_domains())


def foreign_hosts(raw: bytes) -> list[str]:
    """Hosts a reader or mail client could reach that are not unregisterable names.

    A real brand domain may be *shown* in HTML text (https://www.paypal.com/login as link text is
    the attack being modelled) but never be a destination: an href, src or action, a URL in a
    plain-text part or a header, or an address domain.
    """
    headers, parts = _texts(raw)
    destinations = set(_PLAIN_URL.findall(headers)) | set(_ADDRESS_DOMAIN.findall(headers))
    shown: set[str] = set()
    for html, text in parts:
        destinations |= set(_ADDRESS_DOMAIN.findall(text))
        if html:
            destinations |= set(_DESTINATION.findall(text))
            shown |= set(_HOST.findall(_TAGS.sub(" ", text)))
        else:
            destinations |= set(_PLAIN_URL.findall(text))

    def clean(host: str) -> str:
        return host.lower().rstrip(".")

    bad = {h for h in destinations if not is_synthetic_host(clean(h))}
    bad |= {
        h for h in shown - destinations if not (is_synthetic_host(clean(h)) or _official(clean(h)))
    }
    return sorted(bad)


def load_mail_manifest(path: Path) -> list[MailEntry]:
    entries = [
        MailEntry.model_validate(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len({e.id for e in entries}) != len(entries):
        raise ValueError("duplicate ids in the message manifest")
    for e in entries:
        raw = (path.parent / e.file).read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"{e.id}: file is over {MAX_FILE_BYTES} bytes")
        if hashlib.sha256(raw).hexdigest() != e.file_sha256:
            raise ValueError(f"{e.id}: file does not match its recorded hash")
        if e.origin is Origin.SYNTHETIC and (bad := foreign_hosts(raw)):
            raise ValueError(f"{e.id}: {bad[0]!r} is not a reserved/synthetic name")
    return entries


def read_message(manifest: Path, entry: MailEntry) -> bytes:
    return (manifest.parent / entry.file).read_bytes()
