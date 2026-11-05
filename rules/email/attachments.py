"""Rules about attachments, judged from what the sandbox reported: type by content, name, flags.

File names are attacker text, so summaries carry the extension (cut and cleaned) and the detected
type, never the name itself.
"""

import re

from core.email.models import Part
from rules.email import (
    ATTACHMENT,
    DOUBLE_EXTENSION,
    HTML_SMUGGLING,
    MALICIOUS_FILE,
    RTL_OVERRIDE,
    Ctx,
    rule,
)
from rules.email.data import lists

_DOCUMENT_LOOKING = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "txt",
        "rtf",
        "csv",
    ]
)
_RUNS_CODE_MAGIC = frozenset({"exe", "lnk", "elf"})
_ARCHIVE_MAGIC = frozenset({"zip", "rar", "7z", "gz", "bz2", "iso"})


def _attachments(ctx: Ctx) -> list[Part]:
    return [p for p in ctx.scan.parts if p.attachment]


def _ext(name: str | None) -> str:
    if not name or "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].strip().lower()


def _shown(ext: str) -> str:
    return "." + ext if re.fullmatch(r"[a-z0-9]{1,10}", ext) else "(odd)"


def _list(key: str) -> frozenset[str]:
    return frozenset(lists()[key])


@rule("email.dangerous_attachment", "attachment", MALICIOUS_FILE)
def dangerous_attachment(ctx: Ctx) -> str | None:
    dangerous = _list("dangerous_extensions")
    hits = [
        p for p in _attachments(ctx) if _ext(p.filename) in dangerous or p.magic in _RUNS_CODE_MAGIC
    ]
    if not hits:
        return None
    first = hits[0]
    kind = (
        _shown(_ext(first.filename))
        if _ext(first.filename) in dangerous
        else f"{first.magic} content"
    )
    return f"{len(hits)} attachment(s) that can run code, e.g. {kind}"


@rule("email.double_extension", "attachment", DOUBLE_EXTENSION)
def double_extension(ctx: Ctx) -> str | None:
    risky = _list("dangerous_extensions") | _list("macro_extensions") | _list("html_extensions")
    risky |= _list("archive_extensions")
    for p in _attachments(ctx):
        parts = [s.strip() for s in (p.filename or "").lower().split(".")]
        if len(parts) >= 3 and parts[-2] in _DOCUMENT_LOOKING and parts[-1] in risky:
            return f"an attachment pretends to be .{parts[-2]} but ends in {_shown(parts[-1])}"
    return None


@rule("email.rtl_filename", "attachment", RTL_OVERRIDE)
def rtl_filename(ctx: Ctx) -> str | None:
    n = sum("bidi_filename" in p.flags for p in _attachments(ctx))
    return (
        f"{n} attachment name(s) use a right-to-left override to disguise the extension"
        if n
        else None
    )


@rule("email.attachment_type_mismatch", "attachment", ATTACHMENT)
def attachment_type_mismatch(ctx: Ctx) -> str | None:
    expected = lists()["expected_magic"]
    for p in _attachments(ctx):
        ext = _ext(p.filename)
        if ext in expected and p.magic is not None and p.magic not in expected[ext]:
            return f"an attachment named {_shown(ext)} is really {p.magic} content"
    return None


@rule("email.macro_attachment", "attachment", MALICIOUS_FILE)
def macro_attachment(ctx: Ctx) -> str | None:
    macro = _list("macro_extensions")
    hits = [p for p in _attachments(ctx) if _ext(p.filename) in macro or "macroenabled" in p.ctype]
    return f"{len(hits)} Office attachment(s) that can carry macros" if hits else None


@rule("email.html_attachment", "attachment", HTML_SMUGGLING)
def html_attachment(ctx: Ctx) -> str | None:
    html = _list("html_extensions")
    hits = [p for p in _attachments(ctx) if _ext(p.filename) in html or p.magic in ("html", "svg")]
    return (
        f"{len(hits)} HTML or SVG attachment(s): a page that opens from the reader's disk"
        if hits
        else None
    )


@rule("email.archive_attachment", "attachment", ATTACHMENT)
def archive_attachment(ctx: Ctx) -> str | None:
    archives = _list("archive_extensions")
    expected = lists()["expected_magic"]
    hits = [
        p
        for p in _attachments(ctx)
        if _ext(p.filename) in archives
        or (p.magic in _ARCHIVE_MAGIC and _ext(p.filename) not in expected)
    ]
    return (
        f"{len(hits)} archive attachment(s); their contents are not inspected yet" if hits else None
    )
