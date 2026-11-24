"""The evidence dossier (DA5 1a): `python -m core.cli investigate <url | .eml | file>`.

Offline: it opens no socket and calls no provider. It runs the engine's own analysis, then adds what
explains it: the address taken apart, the learned model's reading, where the score came from, and
which stated changes the engine's own scorer confirms would change the verdict
(docs/INVESTIGATE.md).
"""

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from core import sandbox
from core.detonate.models import PageReport
from core.email.engine import MAX_MESSAGE_BYTES, InspectRun
from core.files.engine import MAX_FILE_BYTES, InspectBytes
from core.investigate.dossier import KEYS, SECTIONS, file_dossier, message_dossier, url_dossier
from core.investigate.render import render_html, render_json, render_text

__all__ = [
    "KEYS", "SECTIONS", "investigate", "load_page_report", "render_html", "render_json",
    "render_text",
]  # fmt: skip
_MAX_REPORT_BYTES = 4 * 1024 * 1024


def load_page_report(path: Path) -> PageReport:
    """A saved page report (what the detonator returned; eval/detonate keeps them as JSON).
    Raises OSError if unreadable, ValueError if it is not a page report."""
    with path.open("rb") as f:
        raw = f.read(_MAX_REPORT_BYTES + 1)
    if len(raw) > _MAX_REPORT_BYTES:
        raise ValueError("the page report is over 4 MiB")
    text = raw.decode("utf-8", "replace")
    try:
        return PageReport.model_validate_json(text)
    except ValueError as e:
        if '"verdict"' in text[:2000]:
            raise ValueError(
                "this is a verdict report (the output of `detonate --json`), which holds no page "
                "content; give the saved page report instead"
            ) from e
        raise ValueError("this file is not a page report") from e


def _file(target: str) -> Path | None:
    try:
        path = Path(target)
        return path if path.is_file() else None
    except (OSError, ValueError):  # an address can hold characters a path cannot
        return None


def _read(path: Path, cap: int) -> bytes:
    with path.open("rb") as f:
        return f.read(cap + 1)  # one over the cap, so the engine sees it is too large


def investigate(
    target: str,
    *,
    page_report: PageReport | None = None,
    mail_run: Callable[[bytes], sandbox.Result] | None = None,
    inspect_run: InspectRun | None = None,
    file_run: InspectBytes | None = None,
) -> dict[str, Any]:
    """The dossier of a web address, or of the file at that path (a message if it ends in .eml).
    The `*_run` arguments replace the parser sandbox (tests only). Raises OSError for a file that
    cannot be read and ValueError for a page report given with a file."""
    path = _file(target)
    if path is None:
        return url_dossier(target, page_report)
    if page_report is not None:
        raise ValueError("--page-report belongs to a web address, not to a file")
    if path.suffix.lower() == ".eml":
        return message_dossier(_read(path, MAX_MESSAGE_BYTES), path.name, mail_run, inspect_run)
    data = _read(path, MAX_FILE_BYTES)
    if len(data) <= MAX_FILE_BYTES:
        return file_dossier(path.name, len(data), hashlib.sha256(data).hexdigest(), data, file_run)
    with path.open("rb") as f:  # too large to open: its name, size and hash are all it gets
        sha = hashlib.file_digest(f, "sha256").hexdigest()
    return file_dossier(path.name, path.stat().st_size, sha, None, file_run)
