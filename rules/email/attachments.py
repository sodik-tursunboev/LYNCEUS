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

DOCUMENT_LOOKING = frozenset(
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


def file_ext(name: str | None) -> str:
    if not name or "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].strip().lower()


def shown_ext(ext: str) -> str:
    return "." + ext if re.fullmatch(r"[a-z0-9]{1,10}", ext) else "(odd)"


def ext_list(key: str) -> frozenset[str]:
    return frozenset(lists()[key])


@rule("email.dangerous_attachment", "attachment", MALICIOUS_FILE)
def dangerous_attachment(ctx: Ctx) -> str | None:
    dangerous = ext_list("dangerous_extensions")
    hits = [
        p
        for p in _attachments(ctx)
        if file_ext(p.filename) in dangerous or p.magic in _RUNS_CODE_MAGIC
    ]
    if not hits:
        return None
    first = hits[0]
    kind = (
        shown_ext(file_ext(first.filename))
        if file_ext(first.filename) in dangerous
        else f"{first.magic} content"
    )
    return f"{len(hits)} attachment(s) that can run code, e.g. {kind}"


@rule("email.double_extension", "attachment", DOUBLE_EXTENSION)
def double_extension(ctx: Ctx) -> str | None:
    risky = (
        ext_list("dangerous_extensions")
        | ext_list("macro_extensions")
        | ext_list("html_extensions")
    )
    risky |= ext_list("archive_extensions")
    for p in _attachments(ctx):
        parts = [s.strip() for s in (p.filename or "").lower().split(".")]
        if len(parts) >= 3 and parts[-2] in DOCUMENT_LOOKING and parts[-1] in risky:
            return f"an attachment pretends to be .{parts[-2]} but ends in {shown_ext(parts[-1])}"
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
        ext = file_ext(p.filename)
        if ext in expected and p.magic is not None and p.magic not in expected[ext]:
            return f"an attachment named {shown_ext(ext)} is really {p.magic} content"
    return None


@rule("email.macro_attachment", "attachment", MALICIOUS_FILE)
def macro_attachment(ctx: Ctx) -> str | None:
    macro = ext_list("macro_extensions")
    hits = [
        p for p in _attachments(ctx) if file_ext(p.filename) in macro or "macroenabled" in p.ctype
    ]
    return f"{len(hits)} Office attachment(s) that can carry macros" if hits else None


@rule("email.html_attachment", "attachment", HTML_SMUGGLING)
def html_attachment(ctx: Ctx) -> str | None:
    html = ext_list("html_extensions")
    hits = [
        p for p in _attachments(ctx) if file_ext(p.filename) in html or p.magic in ("html", "svg")
    ]
    return (
        f"{len(hits)} HTML or SVG attachment(s): a page that opens from the reader's disk"
        if hits
        else None
    )


_ACTIVE_WORDS = {
    "script": "runs script", "event_handler": "reacts to events with script",
    "foreign_object": "carries a web page inside", "embedded_form": "holds a form",
    "javascript_link": "links to script", "data_html_link": "links to a page carried inside it",
}  # fmt: skip


@rule("email.svg_active", "active_content", HTML_SMUGGLING)
def svg_active(ctx: Ctx) -> str | None:
    """An SVG image that can act when opened (H1 C2): a picture needs no script, events or forms."""
    hits = [p for p in ctx.scan.parts if p.active]  # attached or inline: both open in a browser
    if not hits:
        return None
    what = sorted({_ACTIVE_WORDS[a] for p in hits for a in p.active})
    return f"{len(hits)} SVG image(s) that {', '.join(what)}: it acts like a web page when opened"


@rule("email.archive_attachment", "attachment", ATTACHMENT)
def archive_attachment(ctx: Ctx) -> str | None:
    archives = ext_list("archive_extensions")
    expected = lists()["expected_magic"]
    hits = [
        p
        for p in _attachments(ctx)
        if file_ext(p.filename) in archives
        or (p.magic in _ARCHIVE_MAGIC and file_ext(p.filename) not in expected)
    ]
    if not hits:
        return None
    closed = sum(1 for f in ctx.files if f.failure == "unsupported")
    note = f"; {closed} in a format that cannot be opened yet (7z, rar or iso)" if closed else ""
    return f"{len(hits)} archive attachment(s){note}"
