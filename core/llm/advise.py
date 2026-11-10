"""Turn a model review into advice on a verdict, with hard limits (ADR-023):

1. It can only ADD suspicion. A "benign" or "unsure" review changes nothing at all, not even the
   wording: a macro that talks the model into "benign" gains nothing, and nothing reassuring from a
   model ever reaches the user.
2. It can never decide. Its signal is in its own category, capped at 0.35, below the 0.5 that makes
   a category count as independent evidence, so it can never supply the second kind of evidence
   that MALICIOUS needs, and a verdict that was not MALICIOUS is never made MALICIOUS by it
   (checked again here as a second wall). Alone it cannot even reach SUSPICIOUS.
3. Only fixed words reach a verdict: the assessment, the confidence and behaviour names from a
   closed list. The model's free-text reason is never stored or shown in a verdict.
4. It runs only after the deterministic analysis found a macro, only against a local model, within
   a time budget, and any failure leaves the verdict exactly as it was.
"""

import asyncio
import logging
from collections.abc import Callable
from functools import partial
from typing import Any

from core.contracts import Evidence, Signal, Verdict, VerdictState
from core.email.engine import EmailAnalysis
from core.files.engine import FileAnalysis
from core.llm.ollama import OllamaClient
from core.llm.review import Review, review_excerpt
from core.risk.scoring import score
from rules.email.data import scoring

log = logging.getLogger(__name__)
CATEGORY = "llm_review"
CAP = 0.35  # below the configured high_weight (0.5): never "independent evidence" on its own
WEIGHTS = {"malicious": 0.35, "suspicious": 0.2}
MIN_CONFIDENCE = 60  # a "malicious" answer less sure of itself than this counts as "suspicious"
MACRO_RULES = frozenset({"content.office_macro", "content.xlm_macro"})
MAX_EXCERPTS = 3  # macro-carrying files reviewed for one verdict
_RANK = {
    VerdictState.UNKNOWN: 0, VerdictState.BENIGN: 0, VerdictState.SUSPICIOUS: 1,
    VerdictState.MALICIOUS: 2,
}  # fmt: skip


def has_macro(verdict: Verdict) -> bool:
    """Did the deterministic analysis find a macro? Only then is the model asked at all."""
    return any(s.rule_id in MACRO_RULES for s in verdict.signals)


def advise(
    verdict: Verdict, evidence: list[Evidence], review: Review, digest: str, model: str
) -> tuple[Verdict, list[Evidence]]:
    """The verdict and evidence with the review's advice added (see the module text). Returns the
    very same objects when the review adds nothing."""
    kind = review.assessment
    if kind == "malicious" and review.confidence < MIN_CONFIDENCE:
        kind = "suspicious"
    if kind not in WEIGHTS or verdict.state is VerdictState.ERROR:
        return verdict, evidence  # benign, unsure, or nothing to advise on: no change of any kind
    behaviours = ", ".join(b for b in review.behaviors if b != "ordinary_automation")
    text = (
        f"A local model ({model}) read the macro and judged it {review.assessment} "
        f"(confidence {review.confidence}): {behaviours or 'no named behaviour'}. Advice only."
    )
    item = Evidence(kind="llm_review", summary=text, sha256=digest)
    signal = Signal(
        rule_id=f"llm.macro_review.{kind}", category=CATEGORY, weight=WEIGHTS[kind],
        description=text, evidence_ids=[item.id],
    )  # fmt: skip
    cfg: dict[str, Any] = dict(scoring())
    cfg["category_caps"] = {**cfg["category_caps"], CATEGORY: CAP}
    signals = [*verdict.signals, signal]
    scored = score(signals, False, cfg)
    state = scored.state
    if _RANK[state] < _RANK[verdict.state]:  # advice never lowers
        state = verdict.state
    if state is VerdictState.MALICIOUS and verdict.state is not VerdictState.MALICIOUS:
        state = VerdictState.SUSPICIOUS  # advice never decides: it cannot make a file malicious
    changed = state is not verdict.state
    risk = (
        None
        if state is VerdictState.UNKNOWN
        else max(scored.risk_score or 0, verdict.risk_score or 0)
    )
    updated = Verdict.model_validate(
        {
            **verdict.model_dump(),
            "state": state,
            "risk_score": risk,
            "confidence": scored.confidence if changed else verdict.confidence,
            "signals": [s.model_dump() for s in signals],
            "evidence_ids": [*verdict.evidence_ids, item.id],
            "recommended_response": scored.recommended_response
            if changed
            else verdict.recommended_response,
            "explanation": f"{verdict.explanation} {text}",
        }
    )
    return updated, [*evidence, item]


class Advisor:
    """Reads macros with a local model and applies the advice. `file_excerpt` gets the macro code of
    a file (bytes -> text) and `part_excerpt` of one part of a message (raw, part path -> text),
    from the sandbox; the text goes to the local model and nowhere else. One review runs at a time
    (a small machine holds one model), and one verdict gets at most `budget` seconds in total,
    waiting included: past that the verdict goes out as the deterministic analysis left it."""

    def __init__(
        self,
        client: OllamaClient,
        file_excerpt: Callable[[bytes], str | None],
        part_excerpt: Callable[[bytes, str], str | None],
        budget: float = 45.0,
    ) -> None:
        self.client, self.budget = client, budget
        self.file_excerpt, self.part_excerpt = file_excerpt, part_excerpt
        self._one_at_a_time = asyncio.Semaphore(1)

    async def _advise(
        self,
        verdict: Verdict,
        evidence: list[Evidence],
        digest: str,
        excerpts: list[Callable[[], str | None]],
    ) -> tuple[Verdict, list[Evidence]]:
        """Review the macro code of each file in turn (the first MAX_EXCERPTS that have any) and
        apply the advice; any failure changes nothing."""
        asked = 0
        try:
            async with asyncio.timeout(self.budget), self._one_at_a_time:
                for get in excerpts:
                    if asked >= MAX_EXCERPTS:
                        break
                    text = await asyncio.to_thread(get)
                    if not text:
                        continue
                    asked += 1
                    review = await review_excerpt(self.client, text)
                    if review is None:
                        continue
                    log.info("local model review: %s (%d)", review.assessment, review.confidence)
                    verdict, evidence = advise(verdict, evidence, review, digest, self.client.model)
        except TimeoutError:
            log.warning("local model review skipped: over its time budget")
        except Exception:  # noqa: BLE001  (advice is optional: never lose the real verdict)
            log.warning("local model review skipped: unexpected failure")
        return verdict, evidence

    async def advise_file(self, analysis: FileAnalysis, data: bytes) -> FileAnalysis:
        report = analysis.report
        if not has_macro(report.verdict):
            return analysis
        verdict, evidence = await self._advise(
            report.verdict,
            list(report.evidence),
            analysis.sha256,
            [lambda: self.file_excerpt(data)],
        )
        if verdict is report.verdict:
            return analysis
        update = {"verdict": verdict, "evidence": tuple(evidence)}
        return analysis.model_copy(update={"report": report.model_copy(update=update)})

    async def advise_message(self, analysis: EmailAnalysis, raw: bytes) -> EmailAnalysis:
        report = analysis.report
        if not has_macro(report.verdict):
            return analysis
        parts = [f.part for f in report.files if f.status == "ok"]
        getters: list[Callable[[], str | None]] = [
            partial(self.part_excerpt, raw, p) for p in parts[:8]
        ]
        verdict, evidence = await self._advise(
            report.verdict, list(report.evidence), analysis.input_sha256, getters
        )
        if verdict is report.verdict:
            return analysis
        update = {"verdict": verdict, "evidence": tuple(evidence)}
        return analysis.model_copy(update={"report": report.model_copy(update=update)})

    async def aclose(self) -> None:
        await self.client.aclose()
