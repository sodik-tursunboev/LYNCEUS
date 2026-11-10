"""One review: the model's answer, accepted only if it is exactly the fixed schema.

Anything else (extra words, an unknown behaviour name, a score out of range, text around the JSON)
is "no answer", never a guess. The reason text is untrusted model output: it is reduced to plain
printable text without addresses before it can reach a verdict's explanation.
"""

import logging
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from core.llm import rubric
from core.llm.ollama import LocalModelError, OllamaClient

log = logging.getLogger(__name__)
Assessment = Literal["malicious", "suspicious", "benign", "unsure"]
Behavior = Literal[
    "runs_programs", "downloads_code", "injects_code", "hides_its_actions", "persists",
    "drops_files", "loads_payload_from_document", "evades_analysis", "steals_data",
    "ordinary_automation",
]  # fmt: skip
_URL = re.compile(r"(?i)\b(?:https?|ftp)://\S+|\bwww\.\S+")


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment: Assessment
    behaviors: Annotated[list[Behavior], Field(max_length=6)]
    confidence: Annotated[int, Field(ge=0, le=100)]
    reason: Annotated[str, Field(max_length=240)]

    def plain_reason(self) -> str:
        """The reason as safe text: printable ASCII, no addresses or markup, 200 characters."""
        text = _URL.sub("[address]", self.reason)
        text = "".join(c if 32 <= ord(c) < 127 else " " for c in text)
        text = re.sub(r"[<>`{}\[\]\\]", "", text)
        return " ".join(text.split())[:200]


def parse_review(text: str) -> Review | None:
    """The review in `text`, or None when it is not exactly a valid one."""
    if len(text) > 4000:
        return None
    try:
        return Review.model_validate_json(text)
    except ValidationError:
        return None


async def review_excerpt(client: OllamaClient, excerpt: str) -> Review | None:
    """Ask the local model. Never raises: no answer (down, slow, off-schema) is None, and the
    verdict stays exactly what the deterministic analysis said."""
    if not excerpt.strip():
        return None
    try:
        text = await client.generate(rubric.SYSTEM, rubric.build_prompt(excerpt), rubric.SCHEMA)
    except LocalModelError as e:
        log.warning("local model review skipped: %s", e.reason)
        return None
    except Exception:  # noqa: BLE001
        log.warning("local model review skipped: unexpected failure")
        return None
    review = parse_review(text)
    if review is None:
        log.warning("local model review skipped: the answer was not in the fixed form")
    return review
