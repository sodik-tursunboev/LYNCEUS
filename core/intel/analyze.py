"""The local analysis first, always; then intelligence, under a deadline; then correlation.

`analyze_url` stays offline and pure. Nothing here can make a verdict wait longer than the
deadline for providers, and nothing here can turn a provider failure into a missing verdict.
"""

import asyncio
import logging
from collections.abc import Callable
from uuid import UUID

from core.contracts import VerdictState
from core.detection.engine import UrlAnalysis, analyze_url
from core.intel.base import IntelOutcome, Subject
from core.intel.orchestrator import Intel
from core.risk.correlate import correlate

log = logging.getLogger(__name__)
NO_OUTCOME = IntelOutcome((), ())


async def analyze_with_intel(
    raw: str, intel: Intel | None, artifact_id: UUID | None = None
) -> tuple[UrlAnalysis, IntelOutcome]:
    local = await asyncio.to_thread(analyze_url, raw, artifact_id)
    if intel is None or local.url is None or local.verdict.state is VerdictState.ERROR:
        return local, NO_OUTCOME
    try:
        outcome = await intel.query(Subject.from_parsed(local.url))
        return correlate(local, outcome), outcome
    except Exception:  # noqa: BLE001  (intelligence must never cost the caller the local verdict)
        log.exception("intelligence step failed; returning the local verdict")
        return local, NO_OUTCOME


def link_analyzer(intel: Intel) -> Callable[[str], UrlAnalysis]:
    """For message links, analysed in a worker thread: local analysis plus the *list feeds* only,
    unless the operator allowed message links to reach outside services (ADR-015)."""

    def analyze(url: str) -> UrlAnalysis:
        local = analyze_url(url)
        if local.url is None or local.verdict.state is VerdictState.ERROR:
            return local
        try:
            return correlate(local, intel.query_sync(Subject.from_parsed(local.url), "email"))
        except Exception:  # noqa: BLE001
            log.exception("intelligence step failed for a message link")
            return local

    return analyze
