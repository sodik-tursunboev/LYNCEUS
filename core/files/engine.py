"""The file engine: one downloaded file in (name, size, hash, and its bytes if small enough), a
verdict out. Built for the Windows agent (M4); it never touches the file system.

It reuses what the message engine already knows about attachments: a file is treated as the single
attachment of an otherwise empty message, so the same rules fire (dangerous or disguised names, a
type that disagrees with the name, macro files, archive contents, PDF actions, smuggling pages) and
the same scoring applies. Bytes are parsed only in the sandbox (`inspect_bytes`); without bytes the
verdict rests on the name and the type the agent reported. A file is never BENIGN.
"""

import logging
import re
from collections.abc import Callable
from typing import get_args
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, ValidationError

from core import hashlists as hashes
from core import sandbox
from core.contracts import Confidence, Evidence, ResponseAction, Signal, Verdict, VerdictState
from core.detection.engine import analyze_url
from core.email import engine as mail
from core.email.engine import ExtractedRef, FileSummary, LinkSummary
from core.email.models import FileBytesReply, HtmlStats, Magic, MessageScan, Part
from core.risk.scoring import Scored, score
from rules.email import Ctx, FileInfo, LinkInfo
from rules.email.data import ruleset_version, scoring

ENGINE_VERSION = "file-1.1.0"
MAX_FILE_BYTES = sandbox.MAX_INPUT_BYTES - 4096  # the sandbox request also carries a small header
NOT_EXAMINED = "This is not evidence of safety: only the name, type and structure were examined."
MAGICS = frozenset(get_args(Magic))
INSPECTABLE = frozenset(
    [
        "pdf",
        "zip",
        "gz",
        "bz2",
        "xz",
        "tar",
        "png",
        "jpeg",
        "gif",
        "bmp",
        "tiff",
        "webp",
        "html",
        "svg",
    ]
)
_BIDI = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
log = logging.getLogger(__name__)
InspectBytes = Callable[[bytes], sandbox.Result]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class HashMatch(_Frozen):
    """A hash that is on a known-bad list: which kind, which list, and what it matched."""

    algorithm: str
    source: str
    where: str  # "file" or "archive entry"


class FileReport(_Frozen):
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    reason: str | None  # why the file was not (fully) analysed
    inspected: bool  # True when its contents were opened in the sandbox
    files: tuple[FileSummary, ...]
    links: tuple[LinkSummary, ...]
    hashes: dict[str, str] = {}  # noqa: RUF012  (sha256, sha1 and md5 of the file, when its bytes were given)
    hash_matches: tuple[HashMatch, ...] = ()
    hash_lists: int = 0  # how many known-bad lists were consulted (the built-in one included)


class FileAnalysis(_Frozen):
    sha256: str
    report: FileReport
    urls: tuple[ExtractedRef, ...]
    origin_host: str | None


def run_inspect_bytes(data: bytes) -> sandbox.Result:
    return sandbox.run("main.py", sandbox.frame({"op": "inspect_bytes"}, data), mail.INSPECT_LIMITS)


def _flags(name: str) -> tuple[str, list[str]]:
    flags: list[str] = []
    if _BIDI.search(name):
        flags.append("bidi_filename")
        name = _BIDI.sub("?", name)
    if _CONTROL.search(name):
        flags.append("control_chars_in_filename")
        name = _CONTROL.sub("?", name)
    if "/" in name or "\\" in name:
        flags.append("path_in_filename")
        name = re.split(r"[\\/]", name)[-1]
    if len(name) > 255:
        flags.append("long_filename")
        name = name[:255]
    return name or "unnamed", flags


def _scan(
    name: str,
    flags: list[str],
    size: int,
    digest: str,
    magic: str | None,
    html: dict[str, int] | None,
) -> MessageScan:
    """An otherwise empty message holding this one file as its attachment."""
    shown = min(size, 64 * 1024 * 1024)
    part = Part.model_validate(
        {"path": "1", "ctype": "application/octet-stream", "charset": None,
         "disposition": "attachment", "filename": name, "size": shown, "sha256": digest,
         "magic": magic, "attachment": True, "flags": flags}
    )  # fmt: skip
    return MessageScan.model_validate(
        {
            "v": 1, "size": shown, "sha256": digest, "limits_hit": [], "defects": [],
            "headers": {
                "from": [], "from_count": 0, "reply_to": [], "return_path": [], "sender": [],
                "recipient_count": 0, "subject": "", "received_count": 0,
                "auth": {"spf": None, "dkim": None, "dmarc": None, "authserv": None, "count": 0},
                "list_unsubscribe": False, "date_present": False,
            },
            "parts": [part], "links": [], "base": None,
            "html": HtmlStats.model_validate(html or {k: 0 for k in HtmlStats.model_fields}),
            "excerpt": "",
        }
    )  # fmt: skip


def _explain(scored: Scored, signals: list[Signal], inspected: bool) -> str:
    if scored.state is VerdictState.UNKNOWN:
        base = (
            f"{len(signals)} weak signal(s), not enough to call it."
            if signals
            else "No rule fired."
        )
        why = f"{base} {NOT_EXAMINED}"
    else:
        why = f"Score {scored.risk_score} from: {', '.join(s.rule_id for s in signals)}."
    return (
        why
        if inspected
        else why + " The contents were not opened (too large or not an inspectable type)."
    )


def _unscored(
    aid: UUID, digest: str, state: VerdictState, why: str, reason: str, host: str | None
) -> FileAnalysis:
    scored = Scored(state, None, Confidence.LOW, ResponseAction.NONE)
    verdict = mail.build_verdict(aid, scored, [], [], f"{why} {mail.NOT_SAFE}")
    verdict = verdict.model_copy(update={"engine_version": ENGINE_VERSION})
    report = FileReport(
        verdict=verdict, evidence=(), reason=reason, inspected=False, files=(), links=()
    )
    return FileAnalysis(sha256=digest, report=report, urls=(), origin_host=host)


def analyze_file(
    name: str,
    size: int,
    sha256: str,
    data: bytes | None = None,
    *,
    claimed_magic: str | None = None,
    origin_host: str | None = None,
    artifact_id: UUID | None = None,
    run: InspectBytes | None = None,
) -> FileAnalysis:
    """`sha256` and `claimed_magic` come from the agent. With `data` the core recomputes the hash
    and learns the type itself (in the sandbox); the agent's claims are then not used."""
    run = run or run_inspect_bytes
    aid = artifact_id or uuid4()
    digest = sha256.lower() if _SHA256.match(sha256.lower()) else ""
    trimmed = (origin_host or "").lower().rstrip(".")
    host = trimmed if _HOST.match(trimmed) else None
    found = {"sha256": digest} if digest else {}
    if data is not None:
        found = hashes.digests(data)
        actual = found["sha256"]
        if digest and actual != digest:
            why = "The file changed between hashing and sending."
            return _unscored(aid, actual, VerdictState.UNKNOWN, why, "changed_while_reading", host)
        digest = actual
    if not digest:
        return _unscored(
            aid, "0" * 64, VerdictState.UNKNOWN, "No usable hash was given.", "no_hash", host
        )
    # An exact hash match decides on its own, so it is looked up before anything can go wrong: a
    # file too large to open, or a sandbox that is down, must not hide a known-bad file.
    known = hashes.hits_for_file("1", found)
    clean, flags = _flags(name)
    magic: str | None = claimed_magic if claimed_magic in MAGICS else None
    info: FileInfo | None = None
    html: dict[str, int] | None = None
    inspected = False

    def decide() -> FileAnalysis:
        try:
            files = (info,) if info else ()
            scan = _scan(clean, flags, size, digest, magic, html)
            links, _ = mail.resolve_links(scan, 100, mail.file_links(files), analyze_url)
            inside = [h for h in mail.known_bad(scan, files) if h.where == "archive entry"]
            hits = tuple(dict.fromkeys([*known, *inside]))
            ctx = Ctx(scan, tuple(links), None, None, files, hits)
            return _report(aid, digest, found, ctx, links, files, inspected, host)
        except Exception:  # an engine bug is an explicit ERROR, never a silent pass
            log.exception("file analysis failed")
            return _unscored(aid, digest, VerdictState.ERROR, "Analysis failed.", "error", host)

    def stopped(state: VerdictState, why: str, reason: str) -> FileAnalysis:
        """The file could not be opened: UNKNOWN or ERROR, unless its hash already identifies it."""
        return decide() if known else _unscored(aid, digest, state, why, reason, host)

    if data is not None and len(data) > MAX_FILE_BYTES:
        why = f"The file is over the {MAX_FILE_BYTES}-byte limit for opening."
        return stopped(VerdictState.UNKNOWN, why, "too_large")
    if data is not None:
        try:
            result = run(data)
        except sandbox.SandboxUnavailable:
            why = "The parser sandbox is not available, so the file was not opened."
            return stopped(VerdictState.ERROR, why, "sandbox_unavailable")
        except Exception:  # noqa: BLE001  (a launcher bug is an explicit ERROR, never a pass)
            log.exception("sandbox launch failed")
            why = "The parser sandbox failed to run, so the file was not opened."
            return stopped(VerdictState.ERROR, why, "sandbox_error")
        if not result.ok:
            why = f"The sandboxed parser stopped ({result.reason})."
            return stopped(VerdictState.UNKNOWN, why, f"parser_{result.reason}")
        try:
            reply = FileBytesReply.model_validate_json(result.output)
        except ValidationError:
            why = "The parser's reply failed validation and was discarded."
            return stopped(VerdictState.ERROR, why, "worker_output_invalid")
        if reply.file is None:
            why = f"The parser could not read the file ({reply.error})."
            return stopped(VerdictState.UNKNOWN, why, str(reply.error))
        magic, inspected = reply.magic, True
        if reply.file.kind != "none":
            info = FileInfo("1", magic, reply.file, None)
        html = reply.html.model_dump() if reply.html else None
    elif magic in INSPECTABLE and magic not in ("html", "svg"):
        info = FileInfo("1", magic, None, "skipped")  # known to be openable, but not opened
    return decide()


def _report(
    aid: UUID,
    digest: str,
    found: dict[str, str],
    ctx: Ctx,
    links: list[LinkInfo],
    files: tuple[FileInfo, ...],
    inspected: bool,
    host: str | None,
) -> FileAnalysis:
    """Rules, score and report for one file whose facts are in `ctx`."""
    signals, evidence = mail.rule_signals(ctx, digest)
    scored = score(signals, False, scoring())
    if scored.state is VerdictState.MALICIOUS:
        scored = scored._replace(recommended_response=ResponseAction.QUARANTINE)
    verdict = mail.build_verdict(
        aid, scored, signals, evidence, _explain(scored, signals, inspected)
    )
    verdict = verdict.model_copy(
        update={"engine_version": ENGINE_VERSION, "ruleset_version": ruleset_version()}
    )
    matches = tuple(
        HashMatch(algorithm=h.algorithm, source=h.source, where=h.where) for h in ctx.known_bad
    )
    report = FileReport(
        verdict=verdict, evidence=tuple(evidence), reason=None, inspected=inspected,
        files=tuple(mail.describe_file(f) for f in files), links=mail.link_report(links),
        hashes=found, hash_matches=matches, hash_lists=len(hashes.current().status()),
    )  # fmt: skip
    return FileAnalysis(
        sha256=digest, report=report, urls=mail.referenced_urls(links), origin_host=host
    )
