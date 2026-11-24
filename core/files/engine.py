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
from collections.abc import Callable, Iterable
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
from core.intel.base import FileRep
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
_FLAGGED = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
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


class StoredVerdict(_Frozen):
    """What an earlier check of a site found (DA5 phase 3): its state and the ids of the rules that
    fired, read back by the caller from storage. Never the site's name."""

    state: VerdictState
    rules: tuple[str, ...] = ()


OriginLookup = Callable[[str], StoredVerdict | None]  # a host -> the latest stored verdict of it


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
    active: list[str] | None = None,
) -> MessageScan:
    """An otherwise empty message holding this one file as its attachment."""
    shown = min(size, 64 * 1024 * 1024)
    part = Part.model_validate(
        {"path": "1", "ctype": "application/octet-stream", "charset": None,
         "disposition": "attachment", "filename": name, "size": shown, "sha256": digest,
         "magic": magic, "attachment": True, "flags": flags, "active": active or []}
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
    reputation: FileRep | None = None,
    origin_lookup: OriginLookup | None = None,
) -> FileAnalysis:
    """`sha256` and `claimed_magic` come from the agent. With `data` the core recomputes the hash
    and learns the type itself (in the sandbox); the agent's claims are then not used.
    `reputation` (DA2): what VirusTotal's engines say about this hash, already asked by the caller
    (None: not asked, or no answer; that changes nothing). `origin_lookup` (DA5): what an earlier
    check of the origin site stored (the page, the lists, the sandbox); it is extra evidence for
    the origin signal only, and without it, or when it finds nothing or fails, nothing changes."""
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
    active: list[str] = []
    inspected = False

    def decide() -> FileAnalysis:
        try:
            files = (info,) if info else ()
            scan = _scan(clean, flags, size, digest, magic, html, active)
            links, _ = mail.resolve_links(scan, 100, mail.file_links(files), analyze_url)
            inside = [h for h in mail.known_bad(scan, files) if h.where == "archive entry"]
            hits = tuple(dict.fromkeys([*known, *inside]))
            ctx = Ctx(scan, tuple(links), None, None, files, hits)
            installer = _ext(clean) in scoring()["file"]["installer_extensions"] and magic == "exe"
            return _report(
                aid, digest, found, ctx, links, files, inspected, host, installer, reputation,
                origin_lookup,
            )  # fmt: skip
        except Exception:  # an engine bug is an explicit ERROR, never a silent pass
            log.exception("file analysis failed")
            return _unscored(aid, digest, VerdictState.ERROR, "Analysis failed.", "error", host)

    def stopped(state: VerdictState, why: str, reason: str) -> FileAnalysis:
        """The file could not be opened: UNKNOWN or ERROR, unless its hash already identifies it."""
        identified = bool(known) or _reputation_decides(reputation)
        return decide() if identified else _unscored(aid, digest, state, why, reason, host)

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
        active = list(reply.active)
    elif magic in INSPECTABLE and magic not in ("html", "svg"):
        info = FileInfo("1", magic, None, "skipped")  # known to be openable, but not opened
    return decide()


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip().lower() if "." in name else ""


def wants_reputation(name: str) -> bool:
    """DA2: only program-like downloads (programs, installers, scripts, shortcuts, disk images,
    archives, macro-enabled Office files) are worth a hash lookup, and only those are asked: never a
    PDF, a picture or a plain document, so little about what the owner keeps ever leaves."""
    clean, _ = _flags(name)
    return _ext(clean) in scoring()["file"]["reputation_extensions"]


def _reputation_decides(rep: FileRep | None) -> bool:
    return rep is not None and rep.malicious >= scoring()["file"]["vt_certain"]


def _reputation_signal(rep: FileRep | None, digest: str) -> tuple[Signal, Evidence] | None:
    """DA2: what VirusTotal's engines say about the file's hash. Many engines: exact identification
    (like a known-bad list match). A few: a sign of its own kind. One or two: shown, never enough
    alone (a clean installer is flagged by one or two small engines now and then). Nothing, or no
    answer: nothing is added, and that is not evidence of safety."""
    if rep is None or rep.malicious < 1:
        return None
    cfg = scoring()["file"]
    when = f", analysed {rep.analysed:%Y-%m-%d}" if rep.analysed else ""
    summary = f"VirusTotal: {rep.malicious} of {rep.engines} engines flag this file{when}"
    if rep.malicious >= cfg["vt_certain"]:
        rule, category, weight = "file.vt_known_bad", "known_bad", 0.99
    elif rep.malicious >= cfg["vt_flagged"]:
        rule, category, weight = "file.vt_flagged", "reputation", cfg["vt_flagged_weight"]
    else:
        rule, category, weight = "file.vt_weak", "reputation", cfg["vt_weak_weight"]
    ev = Evidence(kind="file_reputation", summary=summary[:500], sha256=digest or None)
    sig = Signal(
        rule_id=rule, category=category, weight=weight, description=summary[:500],
        evidence_ids=[ev.id], attack="T1204.002",
    )  # fmt: skip
    return sig, ev


def _as_download(s: Signal) -> Signal:
    """email.dangerous_attachment on a downloaded installer: still shown, at the file weight."""
    if s.rule_id != "email.dangerous_attachment":
        return s
    return s.model_copy(
        update={
            "weight": scoring()["file"]["installer_weight"],
            "description": "a program (an installer type): it can run code once opened. That is "
            "what an installer is, so it counts only next to another sign",
        }
    )


def _stored_origin(host: str, lookup: OriginLookup | None) -> StoredVerdict | None:
    """DA5: what an earlier check of this site stored, when that flagged it. Storage trouble never
    stops or changes a verdict: the file is then judged as it was before."""
    if lookup is None:
        return None
    try:
        found = lookup(host)
    except Exception:  # noqa: BLE001  (a database problem must not cost the caller a verdict)
        log.warning("the stored verdict of the download's origin could not be read")
        return None
    return found if found is not None and found.state in _FLAGGED else None


def _named(state: VerdictState, rule_ids: Iterable[str]) -> str:
    named = sorted(set(rule_ids))[:3]
    return f"{state.value} ({', '.join(named)})" if named else state.value


def _origin_signal(
    host: str | None, digest: str, lookup: OriginLookup | None = None
) -> tuple[Signal, Evidence] | None:
    """DA1: the site the file was downloaded from (the agent reads it from Windows' download mark),
    judged by the URL rules. A file from a site whose own address looks like phishing is a sign of
    its own kind; a clean or unknown site adds nothing (that is not evidence of safety).
    DA5: what an earlier check of that site stored (its page, the lists, the sandbox) counts too,
    so a site that was already caught is not judged again from its bare address. It only adds: a
    stored verdict that does not flag the site never cancels what the address says."""
    if not host:
        return None
    site = analyze_url(f"https://{host}/")
    seen = _stored_origin(host, lookup)
    address = site.verdict.state if site.verdict.state in _FLAGGED else None
    if address is None and seen is None:
        return None
    told: list[str] = []
    if address is not None:
        rules = (s.rule_id for s in site.verdict.signals)
        told.append(f"a site whose address Lynceus calls {_named(address, rules)}")
    if seen is not None:
        before = _named(seen.state, seen.rules)
        told.append(
            f"had already judged it {before}" if told else f"a site Lynceus judged {before}"
        )
    summary = f"downloaded from {host}, " + " and ".join(told)
    ev = Evidence(kind="file_origin", summary=summary[:500], sha256=digest or None)
    weight = scoring()["file"]["origin_flagged_weight"]
    sig = Signal(
        rule_id="file.origin_flagged", category="origin", weight=weight,
        description=summary[:500], evidence_ids=[ev.id], attack="T1204.002",
    )  # fmt: skip
    return sig, ev


def _report(
    aid: UUID,
    digest: str,
    found: dict[str, str],
    ctx: Ctx,
    links: list[LinkInfo],
    files: tuple[FileInfo, ...],
    inspected: bool,
    host: str | None,
    installer: bool = False,
    reputation: FileRep | None = None,
    origin_lookup: OriginLookup | None = None,
) -> FileAnalysis:
    """Rules, score and report for one file whose facts are in `ctx`. `installer`: a program with an
    installer's name, which weighs less as a download than as an attachment (DA1). `reputation`:
    what VirusTotal says about its hash (DA2). `origin_lookup`: what was stored about its origin
    site (DA5)."""
    signals, evidence = mail.rule_signals(ctx, digest)
    if installer:
        signals = [_as_download(s) for s in signals]
    origin = _origin_signal(host, digest, origin_lookup)
    if origin is not None:
        signals, evidence = [*signals, origin[0]], [*evidence, origin[1]]
    rep = _reputation_signal(reputation, digest)
    if rep is not None:
        signals, evidence = [*signals, rep[0]], [*evidence, rep[1]]
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
