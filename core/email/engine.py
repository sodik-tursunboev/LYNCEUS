"""The message engine: raw RFC 822 bytes in, verdict and evidence out (ADR-014).

Pipeline: size check, sandboxed parse, strict validation of the worker's reply, every link through
the URL engine, rules, score. Nothing here parses the message itself and nothing opens a socket.
A failure at any stage is UNKNOWN or ERROR with a reason; none is ever BENIGN, and a message is
never BENIGN at all in M2 (absence of rules proves nothing).
"""

import hashlib
import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import ada_url
from pydantic import BaseModel, ConfigDict, ValidationError

from core import hashlists as hashes
from core import sandbox
from core.contracts import Confidence, Evidence, ResponseAction, Signal, Verdict, VerdictState
from core.detection.engine import UrlAnalysis, analyze_url
from core.email.models import (
    ArchiveScan,
    ContentScan,
    FileReply,
    ImageScan,
    Link,
    MessageScan,
    Part,
    PdfScan,
    WorkerReply,
)
from core.risk.scoring import Scored, score
from core.urls.parse import ParsedUrl, parse_url
from rules.email import RULES, Ctx, FileInfo, HashHit, LinkInfo
from rules.email.data import ruleset_version, scoring

ENGINE_VERSION = "email-1.2.0"
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
_NOT_SAFE = (
    "This is not evidence of safety: only the message structure and its links were examined."
)
_ABSOLUTE = re.compile(r"^\s*(?:[a-zA-Z][a-zA-Z0-9+.\-]*:|//|\\\\)")
_BARE_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:[/:?#]\S*)?$", re.I)
SANDBOX_LIMITS = sandbox.Limits(memory_mb=512, cpu_seconds=10, wall_seconds=20)
INSPECT_LIMITS = sandbox.Limits(memory_mb=1024, cpu_seconds=20, wall_seconds=40)
INSPECT_CAP = 8  # attachments opened per message; the rest are reported as skipped
INSPECT_WORKERS = 3  # sandboxes running at once for one message
_INSPECTABLE = frozenset(
    [
        "pdf", "zip", "gz", "bz2", "xz", "tar", "png", "jpeg", "gif", "bmp", "tiff", "webp",
        "exe", "lnk", "ole", "rtf", "html", "svg",
    ]
)  # fmt: skip
_MAX_LOOK_INSIDE = (
    1024 * 1024
)  # an attachment with no known magic is searched as possible script text
_UNSUPPORTED = frozenset(["7z", "rar", "iso"])  # named, not opened: no safe parser yet
log = logging.getLogger(__name__)
InspectRun = Callable[[bytes, str], sandbox.Result]
LinkAnalyzer = Callable[[str], UrlAnalysis]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class LinkSummary(_Frozen):
    part: str
    kind: str
    flags: tuple[str, ...]
    normalized_url: str | None
    host: str | None
    state: VerdictState | None  # the URL engine's verdict; None when the link was not analysed
    risk_score: int | None
    rules: tuple[str, ...]


class MessageSummary(_Frozen):
    size: int
    parts: int
    attachments: int
    links: int
    links_analyzed: int
    relative_links_skipped: int
    limits_hit: tuple[str, ...]
    defects: tuple[str, ...]


class FileSummary(_Frozen):
    """What was found in one attachment, in fixed words and numbers (never file content)."""

    part: str
    kind: str  # archive, pdf, image, none, or why it was not opened
    status: str  # ok, or the failure: timeout, crashed, invalid, unsupported, skipped, ...
    facts: tuple[str, ...]


class EmailReport(_Frozen):
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    reason: str | None  # why the message was not (fully) analysed
    summary: MessageSummary | None
    links: tuple[LinkSummary, ...]
    files: tuple[FileSummary, ...] = ()


class ExtractedRef(_Frozen):
    """What storage keeps about a link: a hash and a host, never the URL (ADR-007)."""

    url_sha256: str
    host: str | None
    registered_domain: str | None
    position: int


class EmailAnalysis(_Frozen):
    input_sha256: str
    report: EmailReport
    urls: tuple[ExtractedRef, ...]


def _result(raw_hash: str, verdict: Verdict, reason: str | None) -> EmailAnalysis:
    report = EmailReport(verdict=verdict, evidence=(), reason=reason, summary=None, links=())
    return EmailAnalysis(input_sha256=raw_hash, report=report, urls=())


def _verdict(
    artifact_id: UUID, scored: Scored, signals: list[Signal], evidence: list[Evidence], why: str
) -> Verdict:
    return Verdict(
        artifact_id=artifact_id,
        state=scored.state,
        risk_score=scored.risk_score,
        confidence=scored.confidence,
        signals=signals,
        evidence_ids=[e.id for e in evidence],
        provider_results=[],
        recommended_response=scored.recommended_response,
        applied_response=ResponseAction.NONE,
        explanation=why,
        engine_version=ENGINE_VERSION,
        ruleset_version=ruleset_version(),
    )


def _unscored(
    artifact_id: UUID, raw_hash: str, state: VerdictState, why: str, reason: str
) -> EmailAnalysis:
    scored = Scored(state, None, Confidence.LOW, ResponseAction.NONE)
    return _result(raw_hash, _verdict(artifact_id, scored, [], [], f"{why} {_NOT_SAFE}"), reason)


def run_sandbox(raw: bytes) -> sandbox.Result:
    return sandbox.run("main.py", sandbox.frame({"op": "mime"}, raw), SANDBOX_LIMITS)


def run_inspect(raw: bytes, path: str) -> sandbox.Result:
    """Open one attachment of `raw`, addressed by part path, in its own sandbox process."""
    header: dict[str, object] = {"op": "inspect", "path": path}
    return sandbox.run("main.py", sandbox.frame(header, raw), INSPECT_LIMITS)


def _inspect_one(raw: bytes, part: Part, run: InspectRun) -> tuple[FileInfo, str]:
    def failed(why: str) -> tuple[FileInfo, str]:
        return FileInfo(part.path, part.magic, None, why), part.sha256

    try:
        result = run(raw, part.path)
    except sandbox.SandboxUnavailable:
        return failed("sandbox_unavailable")
    except Exception:  # noqa: BLE001  (one attachment failing must not end the analysis)
        log.exception("attachment inspection failed to start")
        return failed("sandbox_error")
    if not result.ok:
        return failed(result.reason)
    try:
        reply = FileReply.model_validate_json(result.output)
    except ValidationError:
        return failed("invalid")
    if reply.file is None:
        return failed(str(reply.error))
    return FileInfo(part.path, part.magic, reply.file, None), part.sha256


def _inspect_files(raw: bytes, scan: MessageScan, run: InspectRun) -> tuple[FileInfo, ...]:
    """Each distinct inspectable attachment gets its own sandbox process (up to INSPECT_CAP)."""
    infos: dict[str, FileInfo] = {}
    jobs: list[Part] = []
    for part in scan.parts:
        if not part.attachment:
            continue
        if part.magic in _UNSUPPORTED:
            infos[part.path] = FileInfo(part.path, part.magic, None, "unsupported")
        elif part.magic in _INSPECTABLE or (
            part.magic is None and 0 < part.size <= _MAX_LOOK_INSIDE
        ):
            if len(jobs) < INSPECT_CAP:
                jobs.append(part)
            else:
                infos[part.path] = FileInfo(part.path, part.magic, None, "skipped")
    unique: dict[str, Part] = {}
    for part in jobs:
        unique.setdefault(part.sha256, part)  # identical bytes are inspected once
    with ThreadPoolExecutor(max_workers=INSPECT_WORKERS) as pool:
        outcomes = pool.map(lambda p: _inspect_one(raw, p, run), unique.values())
        done = {digest: info for info, digest in outcomes}
    for part in jobs:
        base = done[part.sha256]
        infos[part.path] = FileInfo(part.path, part.magic, base.scan, base.failure)
    return tuple(infos[p.path] for p in scan.parts if p.path in infos)


def _qr_url(payload: str) -> str | None:
    text = payload.strip()
    if _ABSOLUTE.match(text):
        return text
    return "https://" + text if _BARE_DOMAIN.match(text) else None


def _file_links(files: tuple[FileInfo, ...]) -> list[Link]:
    """URLs found inside attachments, so they go through the URL engine like any other link."""
    out: list[Link] = []
    for f in files:
        if isinstance(f.scan, PdfScan):
            out += [
                Link(part=f.part, kind="pdf_uri", url=u, text="", flags=[]) for u in f.scan.uris
            ]
        elif isinstance(f.scan, ImageScan):
            for payload in f.scan.qr:
                if url := _qr_url(payload):
                    out.append(Link(part=f.part, kind="qr", url=url, text="", flags=[]))
        elif isinstance(f.scan, ContentScan):
            out += [Link(part=f.part, kind="code", url=u, text="", flags=[]) for u in f.scan.urls]
        elif isinstance(f.scan, ArchiveScan):
            found = list(f.scan.external_refs)
            for m in f.scan.members:
                if m.content:
                    found += m.content.urls
            out += [Link(part=f.part, kind="code", url=u, text="", flags=[]) for u in found[:100]]
    return out


def _known_bad(scan: MessageScan, files: tuple[FileInfo, ...]) -> tuple[HashHit, ...]:
    """Attachments and archive entries whose SHA-256 is on a known-bad list on this machine."""
    hits: list[HashHit] = []
    for p in scan.parts:
        if p.attachment:
            hits += hashes.hits_for_file(p.path, {"sha256": p.sha256})
    for f in files:
        if isinstance(f.scan, ArchiveScan):
            hits += hashes.hits_for_members(f.part, [m.sha256 for m in f.scan.members])
    return tuple(hits)


def _content_facts(s: ContentScan) -> list[str]:
    """Fixed words and numbers about what was found inside (never the code)."""
    facts = [f"{n}x {name.replace('_', ' ')}" if n > 1 else name.replace("_", " ")
             for name, n in sorted(s.indicators.items())]  # fmt: skip
    if s.layers:
        facts.append(f"{s.layers} hidden layer(s) unwrapped")
    facts += [f"hidden {name} program" for name, n in sorted(s.embedded.items()) if n]
    if s.urls:
        facts.append(f"{len(s.urls)} address(es) in the code")
    if s.eicar:
        facts.append("EICAR test file")
    if s.truncated:
        facts.append("search stopped at a size limit")
    return facts


def _describe(f: FileInfo) -> FileSummary:
    s = f.scan
    if s is None:
        return FileSummary(
            part=f.part, kind=f.magic or "unknown", status=f.failure or "none", facts=()
        )
    facts: list[str] = []
    if isinstance(s, ArchiveScan):
        facts = [s.format, f"{s.entries} entries", f"{s.total_size} bytes declared"]
        facts += [f"{n} {what}" for n, what in (
            (s.encrypted, "encrypted"), (s.traversal, "path traversal"), (s.nested, "nested"),
        ) if n]  # fmt: skip
        facts += [f"stopped at {limit}" for limit in s.limits]
    elif isinstance(s, PdfScan):
        facts = [f"parse {s.parse}", f"{s.pages} pages", f"{len(s.uris)} links"]
        facts += [f"{n} {what}" for n, what in (
            (s.javascript, "javascript"), (s.launch, "launch"),
            (s.embedded_files, "embedded files"), (s.submit_form, "form submit"),
            (s.rich_media, "rich media"),
        ) if n]  # fmt: skip
        facts += [name for name, on in (("xfa", s.xfa), ("encrypted", s.encrypted)) if on]
    elif isinstance(s, ImageScan):
        facts = [f"{s.format or '?'} {s.width}x{s.height}", f"parse {s.parse}"]
        if s.qr:
            facts.append(f"{len(s.qr)} QR code(s)")
    elif isinstance(s, ContentScan):
        facts = [f"{s.family} content"] + _content_facts(s)
    if isinstance(s, ArchiveScan):
        facts += [f"office document ({s.office})" if s.office else ""]
        facts += [name for name, on in (
            ("macro project", s.vba_project), ("remote template", s.remote_template),
            ("DDE field", s.dde),
        ) if on]  # fmt: skip
        facts = [x for x in facts if x]
        inside = [m for m in s.members if m.content and m.content.indicators]
        facts += [f"{len(s.members)} entries hashed"] if s.members else []
        facts += [f"{len(inside)} entries with code indicators"] if inside else []
    return FileSummary(part=f.part, kind=s.kind, status="ok", facts=tuple(facts))


def _absolute(url: str, kind: str, base: str | None) -> str | None:
    """The URL a browser would load, or None for a relative link we cannot resolve."""
    if kind in ("text", "pdf_uri", "qr", "code") or _ABSOLUTE.match(url):
        return url
    if base is None:
        return None
    try:
        return str(ada_url.join_url(base, url))
    except ValueError:
        return None


def _links(
    scan: MessageScan, cap: int, extra: list[Link], analyze: LinkAnalyzer
) -> tuple[list[LinkInfo], int]:
    base = scan.base if scan.base and _ABSOLUTE.match(scan.base) else None
    analysed: dict[str, UrlAnalysis] = {}
    infos: list[LinkInfo] = []
    relative = 0
    for link in [*scan.links, *extra]:
        url = _absolute(link.url, link.kind, base)
        if url is None:
            relative += 1
            continue
        analysis = analysed.get(url)
        if analysis is None and len(analysed) < cap:
            analysis = analysed[url] = analyze(url)
        parsed = analysis.url if analysis is not None else None
        if parsed is None and analysis is None:
            parsed_or_failure = parse_url(url)
            parsed = parsed_or_failure if isinstance(parsed_or_failure, ParsedUrl) else None
        infos.append(LinkInfo(link.part, link.kind, tuple(link.flags), link.text, parsed, analysis))
    return infos, relative


def _sender(scan: MessageScan) -> tuple[UrlAnalysis | None, str | None]:
    if not scan.headers.from_:
        return None, None
    domain = scan.headers.from_[0].domain.strip().lower()
    if not domain or len(domain) > 253 or "/" in domain or "@" in domain:
        return None, None
    return analyze_url(f"https://{domain}/"), domain


def _signals(ctx: Ctx, raw_hash: str) -> tuple[list[Signal], list[Evidence]]:
    weights = scoring()["weights"]
    signals: list[Signal] = []
    evidence: list[Evidence] = []
    for r in sorted(RULES, key=lambda r: r.id):
        summary = r.check(ctx)
        if summary is None:
            continue
        ev = Evidence(kind="email_rule", summary=summary, sha256=raw_hash)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=r.id,
                category=r.category,
                weight=weights[r.id],
                description=summary,
                evidence_ids=[ev.id],
                attack=r.attack,
            )  # fmt: skip
        )
    best: dict[str, tuple[Signal, str, int]] = {}  # URL rule -> strongest signal, link hash, count
    for link in ctx.links:
        if link.analysis is None or link.parsed is None:
            continue
        for s in link.analysis.verdict.signals:
            seen = best.get(s.rule_id)
            if seen is None or s.weight > seen[0].weight:
                best[s.rule_id] = (s, link.parsed.url_sha256, (seen[2] if seen else 0) + 1)
            else:
                best[s.rule_id] = (seen[0], seen[1], seen[2] + 1)
    for rule_id, (s, url_hash, n) in sorted(best.items()):
        text = f"{n} link(s): {s.description}" if n > 1 else f"link: {s.description}"
        ev = Evidence(kind="link_rule", summary=text, sha256=url_hash)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=rule_id,
                category=f"link.{s.category}",
                weight=s.weight,
                description=text,
                evidence_ids=[ev.id],
                attack=s.attack,
            )  # fmt: skip
        )
    return signals, evidence


def _explain(scored: Scored, signals: list[Signal], scan: MessageScan) -> str:
    if scored.state is VerdictState.UNKNOWN:
        base = (
            f"{len(signals)} weak signal(s), not enough to call it."
            if signals
            else "No rule fired."
        )
        why = f"{base} {_NOT_SAFE}"
    else:
        why = f"Score {scored.risk_score} from: {', '.join(s.rule_id for s in signals)}."
    if scan.limits_hit:
        why += f" Partial analysis: the scan stopped at {', '.join(scan.limits_hit)}."
    return why


def _summary(scan: MessageScan, links: list[LinkInfo], relative: int) -> MessageSummary:
    return MessageSummary(
        size=scan.size,
        parts=len(scan.parts),
        attachments=sum(p.attachment for p in scan.parts),
        links=len(links) + relative,  # message links plus URLs found inside attachments
        links_analyzed=sum(1 for link in links if link.analysis is not None),
        relative_links_skipped=relative,
        limits_hit=tuple(scan.limits_hit),
        defects=tuple(scan.defects),
    )


def _link_report(links: list[LinkInfo]) -> tuple[LinkSummary, ...]:
    out = []
    for link in links:
        v = link.analysis.verdict if link.analysis else None
        out.append(
            LinkSummary(
                part=link.part,
                kind=link.kind,
                flags=link.flags,
                normalized_url=link.parsed.normalized if link.parsed else None,
                host=link.parsed.host if link.parsed else None,
                state=v.state if v else None,
                risk_score=v.risk_score if v else None,
                rules=tuple(s.rule_id for s in v.signals) if v else (),
            )  # fmt: skip
        )
    return tuple(out)


def _refs(links: list[LinkInfo]) -> tuple[ExtractedRef, ...]:
    seen: dict[str, ExtractedRef] = {}
    for link in links:
        if link.parsed is not None and link.parsed.url_sha256 not in seen:
            p = link.parsed
            seen[p.url_sha256] = ExtractedRef(
                url_sha256=p.url_sha256, host=p.host, registered_domain=p.registered_domain,
                position=len(seen),
            )  # fmt: skip
    return tuple(seen.values())


def analyze_message(
    raw: bytes,
    artifact_id: UUID | None = None,
    run: Callable[[bytes], sandbox.Result] | None = None,
    inspect_run: InspectRun | None = None,
    link_analyzer: LinkAnalyzer | None = None,
) -> EmailAnalysis:
    run = run or run_sandbox  # looked up at call time, so tests can substitute it
    inspect_run = inspect_run or run_inspect
    analyze_link = link_analyzer or analyze_url  # with intelligence when the caller supplies it
    aid = artifact_id or uuid4()
    raw_hash = hashlib.sha256(raw).hexdigest()
    if not raw.strip():
        return _unscored(aid, raw_hash, VerdictState.UNKNOWN, "The message is empty.", "empty")
    if len(raw) > MAX_MESSAGE_BYTES:
        why = f"The message is over the {MAX_MESSAGE_BYTES}-byte limit."
        return _unscored(aid, raw_hash, VerdictState.UNKNOWN, why, "too_large")
    try:
        result = run(raw)
    except sandbox.SandboxUnavailable:
        why = "The parser sandbox is not available, so nothing was parsed."
        return _unscored(aid, raw_hash, VerdictState.ERROR, why, "sandbox_unavailable")
    except Exception:  # a launcher bug is an explicit ERROR, never a 500 and never a pass
        log.exception("sandbox launch failed")
        why = "The parser sandbox failed to run, so nothing was parsed."
        return _unscored(aid, raw_hash, VerdictState.ERROR, why, "sandbox_error")
    if not result.ok:
        why = f"The sandboxed parser stopped ({result.reason})."
        return _unscored(aid, raw_hash, VerdictState.UNKNOWN, why, f"parser_{result.reason}")
    try:
        reply = WorkerReply.model_validate_json(result.output)
    except ValidationError:
        why = "The parser's reply failed validation and was discarded."
        return _unscored(aid, raw_hash, VerdictState.ERROR, why, "worker_output_invalid")
    if reply.scan is None:
        why = f"The parser could not read the message ({reply.error})."
        return _unscored(aid, raw_hash, VerdictState.UNKNOWN, why, str(reply.error))
    try:
        scan = reply.scan
        files = _inspect_files(raw, scan, inspect_run)
        cap = int(scoring()["thresholds"]["link_cap"])
        links, relative = _links(scan, cap, _file_links(files), analyze_link)
        sender, from_domain = _sender(scan)
        ctx = Ctx(scan, tuple(links), sender, from_domain, files, _known_bad(scan, files))
        signals, evidence = _signals(ctx, raw_hash)
        scored = score(signals, False, scoring())
        if scored.state is VerdictState.MALICIOUS:
            scored = scored._replace(recommended_response=ResponseAction.QUARANTINE)
        verdict = _verdict(aid, scored, signals, evidence, _explain(scored, signals, scan))
        report = EmailReport(
            verdict=verdict, evidence=tuple(evidence), reason=None,
            summary=_summary(scan, links, relative), links=_link_report(links),
            files=tuple(_describe(f) for f in files),
        )  # fmt: skip
        return EmailAnalysis(input_sha256=raw_hash, report=report, urls=_refs(links))
    except Exception:  # an engine bug is an explicit ERROR, never a silent pass
        log.exception("message analysis failed")
        return _unscored(aid, raw_hash, VerdictState.ERROR, "Analysis failed.", "error")


# What the file engine (core/files) reuses: the same rules, links, verdicts and summaries.
rule_signals = _signals
build_verdict = _verdict
file_links = _file_links
resolve_links = _links
describe_file = _describe
referenced_urls = _refs
link_report = _link_report
known_bad = _known_bad
NOT_SAFE = _NOT_SAFE
unscored = _unscored
