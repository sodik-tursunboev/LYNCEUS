"""Page detonation (D1, ADR-025): open a URL in a throwaway, locked-down browser and judge the page.

`detonate_url` is the one entry point the CLI, the API and the evaluation use: the URL verdict
(rules, then intelligence when given) first, then the page, then one verdict over all of it.
"""

import base64
import json
import logging

from core import sandbox
from core.detection.engine import UrlAnalysis, analyze_url
from core.detonate.models import PageReport
from core.detonate.runner import Unavailable, detonate

log = logging.getLogger(__name__)
SCREENSHOT_LIMITS = sandbox.Limits(memory_mb=256, cpu_seconds=5, wall_seconds=10.0)

__all__ = ["PageReport", "Unavailable", "detonate", "detonate_url", "safe_screenshot"]


def safe_screenshot(b64: str | None) -> str | None:
    """The detonator's screenshot, decoded and re-encoded in the parser sandbox (the core never
    decodes an image itself). None when there is none or it is not a plain JPEG."""
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
        result = sandbox.run(
            "main.py", sandbox.frame({"op": "reencode_jpeg"}, raw), SCREENSHOT_LIMITS
        )
        reply = json.loads(result.output) if result.ok else {}
    except (ValueError, OSError):
        return None
    jpeg = reply.get("jpeg") if isinstance(reply, dict) else None
    return jpeg if isinstance(jpeg, str) else None


def detonate_url(raw: str, start: UrlAnalysis | None = None) -> tuple[UrlAnalysis, PageReport]:
    """The verdict with the page in it, and the page report. `start` is the URL verdict already
    computed (with intelligence); without one, the offline URL verdict is used."""
    from core.detonate.judge import judge  # here, not at the top: rules.page imports our models

    first = start or analyze_url(raw)
    if first.url is None or first.url.scheme not in ("http", "https"):
        return first, PageReport(status="error", error="not_a_web_url")
    try:
        report = detonate(first.url.normalized)
    except Unavailable as e:
        report = PageReport(status="error", error=str(e))
    return judge(first, report), report
