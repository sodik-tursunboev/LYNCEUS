"""Message rule pack v1. A rule is a pure function: Ctx in, an evidence summary out (None = no hit).

Rules see only what the sandbox worker reported (validated) and what the URL engine concluded
about the message's links. They never see the raw message, and never fetch anything. Summaries
name facts about hosts, types and counts: not subjects, display names, file names or addresses.
"""

from collections.abc import Callable
from dataclasses import dataclass

from core.detection.engine import UrlAnalysis
from core.email.models import ArchiveScan, ImageScan, MessageScan, NoScan, PdfScan
from core.urls.parse import ParsedUrl


@dataclass(frozen=True)
class FileInfo:
    """One attachment as the sandbox inspected it, or why it was not."""

    part: str
    magic: str | None
    scan: ArchiveScan | PdfScan | ImageScan | NoScan | None
    failure: str | None  # timeout, crashed, invalid, unsupported, skipped, ...: scan is None then


@dataclass(frozen=True)
class LinkInfo:
    part: str
    kind: str
    flags: tuple[str, ...]
    text: str
    parsed: ParsedUrl | None  # None: relative with no base, or not a URL at all
    analysis: UrlAnalysis | None  # None past the link cap


@dataclass(frozen=True)
class Ctx:
    scan: MessageScan
    links: tuple[LinkInfo, ...]
    sender: UrlAnalysis | None  # the URL engine's view of the From domain
    from_domain: str | None
    files: tuple[FileInfo, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    attack: str | None
    check: Callable[[Ctx], str | None]


RULES: list[Rule] = []

ATTACHMENT = "T1566.001"  # ATT&CK v20: Phishing: Spearphishing Attachment
LINK = "T1566.002"  # Phishing: Spearphishing Link
CREDENTIALS = "T1598.003"  # Phishing for Information: Spearphishing Link
MALICIOUS_FILE = "T1204.002"  # User Execution: Malicious File
HTML_SMUGGLING = "T1027.006"  # Obfuscated Files or Information: HTML Smuggling
DOUBLE_EXTENSION = "T1036.007"  # Masquerading: Double File Extension
RTL_OVERRIDE = "T1036.002"  # Masquerading: Right-to-Left Override


def rule(
    rule_id: str, category: str, attack: str | None = None
) -> Callable[[Callable[[Ctx], str | None]], Callable[[Ctx], str | None]]:
    def register(fn: Callable[[Ctx], str | None]) -> Callable[[Ctx], str | None]:
        RULES.append(Rule(rule_id, category, attack, fn))
        return fn

    return register


from rules.email import (  # noqa: E402, F401  (importing registers the rules)
    attachments,
    content,
    files,
    links,
    sender,
)
