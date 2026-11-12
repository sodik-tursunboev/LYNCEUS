"""Turn an opened page into signals and score them with the URL's own (D1).

The URL verdict (rules plus intelligence) comes first and is never lost: the page adds signals, the
landing address is run through the URL rules too, and the whole is scored again by the same model
(ADR-013). A page that could not be opened adds nothing and says why; it is never a reason to call
anything safe.
"""

from typing import Any

from core.contracts import Evidence, Signal
from core.detection.engine import UrlAnalysis, _allowlisted, analyze_url, rescore
from core.detonate.models import PageReport
from rules.intel.data import merged_scoring
from rules.page import evaluate, ruleset_version, scoring

NOT_SAFE = (
    "This is not evidence of safety: a phishing page can show a scanner something other than what "
    "it shows a person."
)
_WHY_NOT = {
    "dead": "the page could not be reached or is gone",
    "error": "the sandboxed browser failed",
}


def merged() -> dict[str, Any]:
    base = merged_scoring()
    return {
        "thresholds": base["thresholds"],
        "category_caps": {**base["category_caps"], **scoring()["category_caps"]},
    }


def _landing(start: UrlAnalysis, report: PageReport) -> tuple[list[Signal], list[Evidence]]:
    """URL-rule hits on the landing address that the starting address did not already have. An
    official site (not shared hosting, not a redirector) chooses where it sends you: visa.com to
    visa.pl is Visa's own redirect, not a typosquat (D1 dev half)."""
    if start.url is None or not report.final_url or _allowlisted(start.url):
        return [], []
    landed = analyze_url(report.final_url)
    if landed.url is None or landed.url.registered_domain == start.url.registered_domain:
        return [], []
    seen = {s.rule_id for s in start.verdict.signals}
    signals, evidence = [], []
    for s in landed.verdict.signals:
        if s.rule_id in seen:
            continue
        ev = Evidence(kind="page_landing", summary=f"landing page: {s.description}"[:500],
                      sha256=landed.url.url_sha256)  # fmt: skip
        evidence.append(ev)
        signals.append(s.model_copy(update={"description": ev.summary, "evidence_ids": [ev.id]}))
    return signals, evidence


def page_signals(start: UrlAnalysis, report: PageReport) -> tuple[list[Signal], list[Evidence]]:
    weights = scoring()["weights"]
    digest = start.url.url_sha256 if start.url else start.input_sha256
    signals, evidence = _landing(start, report)
    for r, summary in evaluate(report):
        ev = Evidence(kind="page_rule", summary=summary[:500], sha256=digest)
        evidence.append(ev)
        signals.append(
            Signal(
                rule_id=r.id,
                category=r.category,
                weight=weights[r.id],
                description=summary[:500],
                evidence_ids=[ev.id],
                attack=r.attack,
            )
        )
    return signals, evidence


def judge(start: UrlAnalysis, report: PageReport) -> UrlAnalysis:
    if start.url is None:
        return start
    if report.status in _WHY_NOT:
        note = f" Page not analysed: {_WHY_NOT[report.status]} ({report.error or 'no detail'})."
        signals: list[Signal] = []
        evidence: list[Evidence] = []
    else:
        signals, evidence = page_signals(start, report)
        how = " (it did not finish loading)" if report.status == "partial" else ""
        if report.http_status is not None and report.http_status >= 400:
            how = f" (it answered HTTP {report.http_status})"
        note = f" The page was opened in the sandbox{how}: {len(signals)} page signal(s)."
    return rescore(
        start,
        signals,
        evidence,
        list(start.verdict.provider_results),
        cfg=merged(),
        note=note,
        version_suffix=f"page.{ruleset_version()}",
        engine_suffix="page",
        not_safe=NOT_SAFE,
    )
