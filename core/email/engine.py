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
from uuid import UUID, uuid4

import ada_url
from pydantic import BaseModel, ConfigDict, ValidationError

from core import sandbox
from core.contracts import Confidence, Evidence, ResponseAction, Signal, Verdict, VerdictState
from core.detection.engine import UrlAnalysis, analyze_url
from core.email.models import MessageScan, WorkerReply
from core.risk.scoring import Scored, score
from core.urls.parse import ParsedUrl, parse_url
from rules.email import RULES, Ctx, LinkInfo
from rules.email.data import ruleset_version, scoring

ENGINE_VERSION = "email-1.0.0"
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
_NOT_SAFE = (
    "This is not evidence of safety: only the message structure and its links were examined."
)
_ABSOLUTE = re.compile(r"^\s*(?:[a-zA-Z][a-zA-Z0-9+.\-]*:|//|\\\\)")
SANDBOX_LIMITS = sandbox.Limits(memory_mb=512, cpu_seconds=10, wall_seconds=20)
log = logging.getLogger(__name__)


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


class EmailReport(_Frozen):
    verdict: Verdict
    evidence: tuple[Evidence, ...]
    reason: str | None  # why the message was not (fully) analysed
    summary: MessageSummary | None
    links: tuple[LinkSummary, ...]


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


def _absolute(url: str, kind: str, base: str | None) -> str | None:
    """The URL a browser would load, or None for a relative link we cannot resolve."""
    if kind == "text" or _ABSOLUTE.match(url):
        return url
    if base is None:
        return None
    try:
        return str(ada_url.join_url(base, url))
    except ValueError:
        return None


def _links(scan: MessageScan, cap: int) -> tuple[list[LinkInfo], int]:
    base = scan.base if scan.base and _ABSOLUTE.match(scan.base) else None
    analysed: dict[str, UrlAnalysis] = {}
    infos: list[LinkInfo] = []
    relative = 0
    for link in scan.links:
        url = _absolute(link.url, link.kind, base)
        if url is None:
            relative += 1
            continue
        analysis = analysed.get(url)
        if analysis is None and len(analysed) < cap:
            analysis = analysed[url] = analyze_url(url)
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
        links=len(scan.links),
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
) -> EmailAnalysis:
    run = run or run_sandbox  # looked up at call time, so tests can substitute it
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
        links, relative = _links(scan, int(scoring()["thresholds"]["link_cap"]))
        sender, from_domain = _sender(scan)
        signals, evidence = _signals(Ctx(scan, tuple(links), sender, from_domain), raw_hash)
        scored = score(signals, False, scoring())
        if scored.state is VerdictState.MALICIOUS:
            scored = scored._replace(recommended_response=ResponseAction.QUARANTINE)
        verdict = _verdict(aid, scored, signals, evidence, _explain(scored, signals, scan))
        report = EmailReport(
            verdict=verdict, evidence=tuple(evidence), reason=None,
            summary=_summary(scan, links, relative), links=_link_report(links),
        )  # fmt: skip
        return EmailAnalysis(input_sha256=raw_hash, report=report, urls=_refs(links))
    except Exception:  # an engine bug is an explicit ERROR, never a silent pass
        log.exception("message analysis failed")
        return _unscored(aid, raw_hash, VerdictState.ERROR, "Analysis failed.", "error")
