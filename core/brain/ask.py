"""Ask the local model one closed question. Never raises: no answer is None, and the verdict stays
what the deterministic analysis said."""

import logging
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from core.llm.ollama import LocalModelError

log = logging.getLogger(__name__)
MAX_ANSWER = 6000  # characters; a longer answer is not the short form that was asked for
START, END = "<<<DATA", "DATA>>>"


class Model(Protocol):
    model: str

    async def generate(
        self, system: str, prompt: str, schema: dict[str, Any], images: list[str] | None = None
    ) -> str: ...


def fenced(text: str, limit: int) -> str:
    """Untrusted text, cut and stripped of our own markers, between the markers: it cannot close
    the data block and start talking as the instructions."""
    clean = text.replace(START, " ").replace(END, " ")[:limit]
    return f"{START}\n{clean}\n{END}"


async def ask[T: BaseModel](
    model: Model, system: str, prompt: str, answer: type[T], images: list[str] | None = None
) -> T | None:
    schema = answer.model_json_schema()
    try:
        text = await model.generate(system, prompt, schema, images)
    except LocalModelError as e:
        log.warning("brain skipped: %s", e.reason)
        return None
    except Exception:  # noqa: BLE001  (fixed text: never the prompt, which holds attacker text)
        log.warning("brain skipped: unexpected failure")
        return None
    if len(text) > MAX_ANSWER:
        log.warning("brain skipped: the answer was too long")
        return None
    try:
        return answer.model_validate_json(text)
    except ValidationError:
        log.warning("brain skipped: the answer was not in the fixed form")
        return None
