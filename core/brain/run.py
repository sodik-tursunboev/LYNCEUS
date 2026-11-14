"""The brain as the API uses it: one question at a time (a small machine holds one model), a time
budget per verdict, and the verdict unchanged whenever the brain is slow, down or unsure."""

import asyncio
import logging
from collections.abc import Callable

from core.brain import mail as mail_brain
from core.brain import page as page_brain
from core.brain import script as script_brain
from core.brain import visual as visual_brain
from core.brain.apply import apply
from core.brain.ask import Model
from core.brain.signals import to_signals
from core.config import Settings
from core.detection.engine import UrlAnalysis
from core.detonate.models import PageReport
from core.email.engine import EmailAnalysis
from core.llm.ollama import OllamaClient
from rules.email.data import scoring as mail_scoring
from rules.page import scoring as page_scoring

log = logging.getLogger(__name__)


class Brain:
    def __init__(self, model: Model, timeout: float) -> None:
        self.model, self.timeout = model, timeout
        self._one_at_a_time = asyncio.Lock()

    async def page(
        self, start: UrlAnalysis, report: PageReport, analysis: UrlAnalysis
    ) -> UrlAnalysis:
        """The detonated page's verdict with the brain's checked findings added (or unchanged)."""
        from core.detonate import safe_screenshot
        from core.detonate.judge import judge  # here: rules.page imports the detonator's models

        if start.url is None or not report.alive:
            return analysis
        url, domain = start.url.normalized, start.url.registered_domain
        fired = {s.rule_id for s in analysis.verdict.signals}
        found: list[tuple[str, str]] = []

        async def text() -> list[tuple[str, str]]:  # P2: what the page says it is
            return await page_brain.think(self.model, url, domain, report, fired)

        async def code() -> list[tuple[str, str]]:  # P4: what its own code does
            return await script_brain.think(self.model, domain, report, fired)

        async def picture() -> list[tuple[str, str]]:  # P3: what it looks like (sandboxed copy)
            jpeg = await asyncio.to_thread(safe_screenshot, report.screenshot)
            return await visual_brain.think(self.model, domain, report, jpeg, fired)

        deadline = asyncio.get_running_loop().time() + self.timeout
        try:
            async with asyncio.timeout_at(deadline), self._one_at_a_time:
                for question in (text, code, picture):
                    new = await question()
                    found += new
                    fired |= {rule_id for rule_id, _ in new}  # a later question never repeats it
        except TimeoutError:
            log.warning("brain: time budget reached after %d checked finding(s)", len(found))
        signals = to_signals(found, page_scoring()["weights"], start.url.url_sha256, "page_brain")
        if not signals[0]:
            return analysis
        log.info("brain: %d checked page finding(s)", len(signals[0]))
        return judge(start, report, extra=signals)

    async def mail(self, analysis: EmailAnalysis, raw: bytes) -> EmailAnalysis:
        """A message's verdict with the brain's checked findings added (or unchanged)."""
        report = analysis.report
        if report.reason is not None:
            return analysis  # not analysed (too large, parser stopped): nothing to read
        fired = {s.rule_id for s in report.verdict.signals}
        try:
            async with asyncio.timeout(self.timeout), self._one_at_a_time:
                scan = await asyncio.to_thread(mail_brain.view, raw)
                found = [] if scan is None else await mail_brain.think(self.model, scan, fired)
        except TimeoutError:
            log.warning("brain skipped: over its time budget")
            return analysis
        cfg = mail_scoring()
        signals, added = to_signals(found, cfg["weights"], analysis.input_sha256, "mail_brain")
        if not signals:
            return analysis
        log.info("brain: %d checked message finding(s)", len(signals))
        verdict, evidence = apply(report.verdict, list(report.evidence), signals, added, cfg)
        update = {"verdict": verdict, "evidence": tuple(evidence)}
        return analysis.model_copy(update={"report": report.model_copy(update=update)})

    async def aclose(self) -> None:
        close = getattr(self.model, "aclose", None)
        if close is not None:
            await close()


def mail_in_thread(settings: Settings) -> Callable[[EmailAnalysis, bytes], EmailAnalysis]:
    """For the mailbox poller, which runs in its own thread: each message gets a brain of its own
    on a fresh event loop (an HTTP client cannot cross loops), closed when the message is done."""

    def run(analysis: EmailAnalysis, raw: bytes) -> EmailAnalysis:
        async def once() -> EmailAnalysis:
            brain = build_brain(settings)
            if brain is None:
                return analysis
            try:
                return await brain.mail(analysis, raw)
            finally:
                await brain.aclose()

        try:
            return asyncio.run(once())
        except Exception:  # noqa: BLE001  (the brain is optional: never lose the real verdict)
            log.warning("brain skipped in the mailbox: unexpected failure")
            return analysis

    return run


def build_brain(settings: Settings) -> Brain | None:
    """None unless LYNCEUS_BRAIN is on. The address must be this computer's, else start-up
    stops."""
    if not settings.brain:
        return None
    model = OllamaClient(settings.llm_url, settings.brain_model, timeout=settings.brain_timeout)
    return Brain(model, settings.brain_timeout)
