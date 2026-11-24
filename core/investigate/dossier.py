"""The dossier of one web address, message or file (DA5 1a): offline, from the engines' own output.

Nothing here opens a socket or calls a provider. A section that does not apply says so, one that
would need the network or Docker says it was not asked, and every string is either the input, the
engine's evidence, rule data, or a sentence from `words.py`.
"""

from collections.abc import Callable
from typing import Any

from core import sandbox
from core.contracts import Signal, Verdict, VerdictState
from core.detection.engine import _allowlisted, analyze_url
from core.detonate.judge import judge, merged
from core.detonate.models import PageReport
from core.email.engine import InspectRun, analyze_message
from core.files.engine import InspectBytes, analyze_file
from core.investigate import words
from core.investigate.attribution import (
    attribute,
    counterfactuals,
    not_scored,
    not_tried,
)
from core.urls import popular
from core.urls.parse import HostKind, ParsedUrl, parse_url
from rules.email.data import scoring as email_scoring
from rules.page import asks_credentials, claimed_brand
from rules.url.data import lists, official_domains, scoring

KEYS = ("target", "engine", "verdict", "sections", "attribution", "counterfactuals", "limits")
SECTIONS = (
    "anatomy", "learned", "established", "redirect_chain", "domain", "fetch", "page", "brand",
    "intel",
)  # fmt: skip
_QUERY_KEYS = 50


def _section(status: str, note: str = "", **facts: Any) -> dict[str, Any]:
    return {"status": status, "note": note, "facts": facts}


def _signal(s: Signal) -> dict[str, Any]:
    return {
        "rule_id": s.rule_id, "category": s.category, "weight": s.weight,
        "description": s.description, "attack": s.attack,
    }  # fmt: skip


def _verdict(v: Verdict, reason: str | None) -> dict[str, Any]:
    return {
        "state": v.state.value, "score": v.risk_score, "confidence": v.confidence.value,
        "recommended_response": v.recommended_response.value, "explanation": v.explanation,
        "reason": reason, "signals": [_signal(s) for s in v.signals],
    }  # fmt: skip


def _assemble(
    target: dict[str, Any],
    engine: str,
    verdict: Verdict,
    reason: str | None,
    sections: dict[str, Any],
    allowlisted: bool,
    cfg: Any,
    limits: tuple[str, ...],
) -> dict[str, Any]:
    if reason is None and verdict.state is not VerdictState.ERROR:
        attr = attribute(verdict.signals, allowlisted, cfg)
        attr["matches_verdict"] = (attr["rebuilt_state"], attr["rebuilt_score"]) == (
            verdict.state.value,
            verdict.risk_score,
        )
        if verdict.state is VerdictState.UNKNOWN and verdict.signals:
            attr["note"] = words.SCORE_HIDDEN
        changes = counterfactuals(verdict.signals, allowlisted, cfg, attr)
    else:
        attr, changes = not_scored(cfg), not_tried()
    return {
        "target": target,
        "engine": {
            "name": engine,
            "version": verdict.engine_version,
            "ruleset_version": verdict.ruleset_version,
            "scorer": words.SCORER,
        },  # fmt: skip
        "verdict": _verdict(verdict, reason),
        "sections": {name: sections[name] for name in SECTIONS},
        "attribution": attr,
        "counterfactuals": changes,
        "limits": [*limits, words.LIMIT_NOT_SAFE],
    }


# ---- a web address ----------------------------------------------------------------------------
def _anatomy(u: ParsedUrl) -> dict[str, Any]:
    keys = [p.partition("=")[0] for p in u.query.split("&") if p]  # as written, not decoded
    return _section(
        words.OK,
        normalized=u.normalized, scheme=u.scheme, username=u.username,
        has_password=u.has_password, host=u.host, host_unicode=u.host_unicode,
        host_kind=u.host_kind.value, ip_address=u.ip_address, public_suffix=u.public_suffix,
        registered_domain=u.registered_domain, shared_hosting=u.private_suffix,
        subdomain_labels=u.subdomain.split(".") if u.subdomain else [], port=u.port,
        path=u.path, query_keys=list(dict.fromkeys(keys))[:_QUERY_KEYS],
        fragment_present=bool(u.fragment), flags=[f.value for f in u.flags],
    )  # fmt: skip


def _learned(u: ParsedUrl | None) -> dict[str, Any]:
    from core.learn.model import current  # here: the model's features read the rule pack's lists
    from rules.url.learned import readable

    if u is None:
        return _section(words.NOT_APPLICABLE, words.PARSE_FAILED)
    model = current()
    if model is None:
        return _section(words.NOT_AVAILABLE, words.NO_MODEL)
    domain = u.registered_domain
    if u.host_kind is not HostKind.DOMAIN or domain is None:
        return _section(words.NOT_APPLICABLE, words.MODEL_NEEDS_DOMAIN)
    p, pushes = model.probability(u)
    silenced = (
        words.SILENT_OFFICIAL if domain in official_domains()
        else words.SILENT_POPULAR if popular.is_popular(domain) else None
    )  # fmt: skip
    return _section(
        words.OK, model_version=model.version, registered_domain=domain, probability=p,
        threshold=model.threshold, fired=p >= model.threshold and silenced is None,
        silenced_by=silenced, pushed_by=[readable(t) for t in pushes],
    )  # fmt: skip


def _established(u: ParsedUrl | None) -> dict[str, Any]:
    if u is None:
        return _section(words.NOT_APPLICABLE, words.PARSE_FAILED)
    domain = u.registered_domain
    if u.host_kind is not HostKind.DOMAIN or domain is None:
        return _section(words.NOT_APPLICABLE, words.MODEL_NEEDS_DOMAIN)
    size = len(popular.domains())
    host = u.host or ""
    return _section(
        words.OK, "" if size else words.NO_POPULAR_LIST, registered_domain=domain,
        official_brand=official_domains().get(domain),
        popular=popular.is_popular(domain) if size else None, popular_list_size=size,
        shared_host=any(host == h or host.endswith("." + h) for h in lists()["shared_hosts"]),
        allowlisted=_allowlisted(u),
    )  # fmt: skip


def _fetch(page: PageReport) -> dict[str, Any]:
    return _section(
        words.OK, page_status=page.status, error=page.error, http_status=page.http_status,
        final_url=page.final_url, chain=page.chain, elapsed_ms=page.elapsed_ms,
        browser=page.browser, phone_view=page.phone_view, desktop_status=page.desktop_status,
        second_look=page.second_look, visited_at=page.visited_at,
        tls=page.tls.model_dump(mode="json") if page.tls else None,
    )  # fmt: skip


def _page(start_signals: int, final: Verdict, page: PageReport) -> dict[str, Any]:
    added = final.signals[start_signals:]  # what the existing judge appended to the address's own
    note = (
        words.PAGE_NOT_READ if page.status in ("dead", "error")
        else words.PAGE_ADDED_NOTHING if not added else ""
    )  # fmt: skip
    return _section(words.OK, note, alive=page.alive, signals=[_signal(s) for s in added])


def _brand(page: PageReport, start: ParsedUrl | None) -> dict[str, Any]:
    found = claimed_brand(page)
    landed = parse_url(page.final_url) if page.final_url else start
    return _section(
        words.OK, words.BRAND_FROM_TEXT_ONLY, title=page.title, headings=page.headings,
        claimed_brand=found[0].name if found else None, claimed_in=found[1] if found else None,
        brand_domains=list(found[0].domains) if found else [],
        landing_domain=landed.registered_domain if isinstance(landed, ParsedUrl) else None,
        asks_credentials=asks_credentials(page),
    )  # fmt: skip


def url_dossier(raw: str, page: PageReport | None = None) -> dict[str, Any]:
    start = analyze_url(raw)
    final = start if page is None else judge(start, page)
    u = start.url
    unread = _section(words.NOT_ASKED, words.NEEDS_PAGE_REPORT)
    sections = {
        "anatomy": _anatomy(u) if u else _section(words.NOT_APPLICABLE, words.PARSE_FAILED),
        "learned": _learned(u),
        "established": _established(u),
        "redirect_chain": _section(words.NOT_ASKED, words.NO_VISIT),
        "domain": _section(words.NOT_ASKED, words.NO_DOMAIN_LOOKUP),
        "fetch": _fetch(page) if page else _section(words.NOT_ASKED, words.NO_FETCH),
        "page": _page(len(start.verdict.signals), final.verdict, page) if page else unread,
        "brand": _brand(page, u) if page else unread,
        "intel": _section(words.NOT_ASKED, words.NO_INTEL),
    }
    target = {
        "kind": words.URL, "value": raw, "size": len(raw.encode("utf-8", "surrogatepass")),
        "sha256": start.input_sha256,
    }  # fmt: skip
    limits = words.LIMIT_URL + (words.LIMIT_PAGE if page else words.LIMIT_NO_PAGE)
    return _assemble(
        target, words.ENGINE_PAGE if page else words.ENGINE_URL, final.verdict, start.reason,
        sections, u is not None and _allowlisted(u), merged() if page else scoring(), limits,
    )  # fmt: skip


# ---- a message or a file ----------------------------------------------------------------------
def _not_an_address(**over: dict[str, Any]) -> dict[str, Any]:
    """The sections that only an address or a page can fill, for a message or a file."""
    na = _section(words.NOT_APPLICABLE, words.NOT_AN_ADDRESS)
    sections = {name: na for name in SECTIONS}
    return {**sections, **over}


def message_dossier(
    raw: bytes,
    name: str,
    run: Callable[[bytes], sandbox.Result] | None = None,
    inspect_run: InspectRun | None = None,
) -> dict[str, Any]:
    a = analyze_message(raw, run=run, inspect_run=inspect_run)
    r = a.report
    anatomy = (
        _section(words.NOT_AVAILABLE, words.NOT_PARSED_MESSAGE)
        if r.summary is None
        else _section(
            words.OK,
            summary=r.summary.model_dump(mode="json"),
            links=[x.model_dump(mode="json") for x in r.links],
            files=[x.model_dump(mode="json") for x in r.files],
        )  # fmt: skip
    )
    sections = _not_an_address(
        anatomy=anatomy,
        redirect_chain=_section(words.NOT_ASKED, words.NO_VISIT_LINKS),
        domain=_section(words.NOT_ASKED, words.NO_DOMAIN_LOOKUP_LINKS),
        fetch=_section(words.NOT_ASKED, words.NO_FETCH_LINKS),
        page=_section(words.NOT_APPLICABLE, words.NOT_A_PAGE),
        brand=_section(words.NOT_APPLICABLE, words.NOT_A_PAGE),
        intel=_section(words.NOT_ASKED, words.NO_INTEL_MESSAGE),
    )
    target = {"kind": words.MESSAGE, "value": name, "size": len(raw), "sha256": a.input_sha256}
    return _assemble(
        target,
        words.ENGINE_MESSAGE,
        r.verdict,
        r.reason,
        sections,
        False,
        email_scoring(),
        words.LIMIT_MESSAGE,
    )


def file_dossier(
    name: str,
    size: int,
    sha256: str,
    data: bytes | None,
    run: InspectBytes | None = None,
) -> dict[str, Any]:
    a = analyze_file(name, size, sha256, data, run=run)
    r = a.report
    anatomy = (
        _section(words.NOT_AVAILABLE, words.NOT_PARSED_FILE, name=name, size=size)
        if r.reason
        else _section(
            words.OK,
            name=name,
            size=size,
            hashes=r.hashes,
            inspected=r.inspected,
            contents=[x.model_dump(mode="json") for x in r.files],
            links=[x.model_dump(mode="json") for x in r.links],
        )  # fmt: skip
    )
    sections = _not_an_address(
        anatomy=anatomy,
        intel=_section(
            words.OK,
            words.HASH_LISTS_ONLY,
            hash_lists=r.hash_lists,
            hash_matches=[m.model_dump(mode="json") for m in r.hash_matches],
        ),  # fmt: skip
    )
    for name_ in ("redirect_chain", "domain", "fetch", "page", "brand"):
        sections[name_] = _section(words.NOT_APPLICABLE, words.NO_ADDRESS_OR_PAGE)
    target = {"kind": words.FILE, "value": name, "size": size, "sha256": a.sha256}
    return _assemble(
        target,
        words.ENGINE_FILE,
        r.verdict,
        r.reason,
        sections,
        False,
        email_scoring(),
        words.LIMIT_FILE,
    )
