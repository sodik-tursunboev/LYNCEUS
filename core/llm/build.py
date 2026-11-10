"""Build the advisor from settings, and the two sandbox calls that fetch a macro's code for it."""

import json
import logging

from core import sandbox
from core.config import Settings
from core.email.engine import INSPECT_LIMITS
from core.llm.advise import Advisor
from core.llm.ollama import OllamaClient

log = logging.getLogger(__name__)
_MAX_TEXT = 12_000


def _text(result: sandbox.Result) -> str | None:
    if not result.ok:
        return None
    try:
        reply = json.loads(result.output)
    except ValueError:
        return None
    text = reply.get("excerpt") if isinstance(reply, dict) else None
    return text[:_MAX_TEXT] if isinstance(text, str) and text.strip() else None


def file_excerpt(data: bytes) -> str | None:
    """The macro code of one file, read in the sandbox (None: no macro, or it could not be read)."""
    try:
        return _text(
            sandbox.run("main.py", sandbox.frame({"op": "macro_excerpt"}, data), INSPECT_LIMITS)
        )
    except Exception:  # noqa: BLE001
        return None


def part_excerpt(raw: bytes, path: str) -> str | None:
    """The macro code of one attachment of a message."""
    header: dict[str, object] = {"op": "macro_excerpt", "path": path}
    try:
        return _text(sandbox.run("main.py", sandbox.frame(header, raw), INSPECT_LIMITS))
    except Exception:  # noqa: BLE001
        return None


def build_advisor(settings: Settings) -> Advisor | None:
    """None unless the operator turned the review on. A setting that is not a loopback address stops
    start-up (ValueError), so a macro can never be sent to another machine by a bad setting."""
    if not settings.llm_review:
        return None
    client = OllamaClient(settings.llm_url, settings.llm_model, timeout=settings.llm_timeout)
    log.info(
        "local model review enabled: %s at %s (recovered macro code goes to this computer only)",
        settings.llm_model, client.base,
    )  # fmt: skip
    return Advisor(client, file_excerpt, part_excerpt, budget=settings.llm_timeout)
