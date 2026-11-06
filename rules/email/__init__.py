"""Message rule pack v1. A rule is a pure function: Ctx in, an evidence summary out (None = no hit).

Rules see only what the sandbox worker reported (validated) and what the URL engine concluded
about the message's links. They never see the raw message, and never fetch anything. Summaries
name facts about hosts, types and counts: not subjects, display names, file names or addresses.
"""

from collections.abc import Callable
from dataclasses import dataclass

from core.detection.engine import UrlAnalysis
from core.email.models import ArchiveScan, ContentScan, ImageScan, MessageScan, NoScan, PdfScan
from core.urls.parse import ParsedUrl


@dataclass(frozen=True)
class FileInfo:
    """One attachment as the sandbox inspected it, or why it was not."""

    part: str
    magic: str | None
    scan: ArchiveScan | PdfScan | ImageScan | ContentScan | NoScan | None
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
class HashHit:
    """A file or archive entry whose hash is on a known-bad list (see core/intel/hashes.py)."""

    part: str
    algorithm: str  # sha256, sha1 or md5
    source: str  # the list's name: what vouches for it
    where: str  # "file" or "archive entry"


@dataclass(frozen=True)
class Ctx:
    scan: MessageScan
    links: tuple[LinkInfo, ...]
    sender: UrlAnalysis | None  # the URL engine's view of the From domain
    from_domain: str | None
    files: tuple[FileInfo, ...] = ()
    known_bad: tuple[HashHit, ...] = ()


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
SCRIPTING = "T1059"  # Command and Scripting Interpreter
INGRESS_TOOL = "T1105"  # Ingress Tool Transfer
OBFUSCATION = "T1027"  # Obfuscated Files or Information
PACKING = "T1027.002"  # Software Packing
EMBEDDED_PAYLOAD = "T1027.009"  # Embedded Payloads
RUN_KEY = "T1547.001"  # Registry Run Keys / Startup Folder
PROXY_EXECUTION = "T1218"  # System Binary Proxy Execution
IMPAIR_DEFENSES = "T1562.001"  # Impair Defenses: Disable or Modify Tools
INJECTION = "T1055"  # Process Injection
HIDDEN_WINDOW = "T1564.003"  # Hide Artifacts: Hidden Window
GUI_INPUT = "T1056.002"  # Input Capture: GUI Input Capture
CREDENTIAL_DUMP = "T1003"  # OS Credential Dumping
SANDBOX_EVASION = "T1497"  # Virtualization/Sandbox Evasion
OFFICE_STARTUP = "T1137"  # Office Application Startup
TEMPLATE_INJECTION = "T1221"  # Template Injection
DDE = "T1559.002"  # Inter-Process Communication: Dynamic Data Exchange
MASQUERADE_FILE_TYPE = "T1036.008"  # Masquerading: Masquerade File Type


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
    deep,
    files,
    links,
    sender,
)
