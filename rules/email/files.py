"""Rules about what the sandbox found inside attachments: archives, PDFs, images, saved pages.

Summaries use numbers and fixed words, and an extension only after it is checked against the shape
[a-z0-9]{1,10}; never a file name, an entry name or the text of a link.
"""

from core.email.models import ArchiveScan, ImageScan, PdfScan
from rules.email import (
    ATTACHMENT,
    DOUBLE_EXTENSION,
    HTML_SMUGGLING,
    LINK,
    MALICIOUS_FILE,
    Ctx,
    rule,
)
from rules.email.attachments import DOCUMENT_LOOKING, ext_list, shown_ext
from rules.email.data import scoring

_RUNS_CODE_MAGIC = ("exe", "elf", "lnk")


def _archives(ctx: Ctx) -> list[tuple[str, ArchiveScan]]:
    return [(f.part, f.scan) for f in ctx.files if isinstance(f.scan, ArchiveScan)]


def _pdfs(ctx: Ctx) -> list[PdfScan]:
    return [f.scan for f in ctx.files if isinstance(f.scan, PdfScan)]


def _images(ctx: Ctx) -> list[ImageScan]:
    return [f.scan for f in ctx.files if isinstance(f.scan, ImageScan)]


def _mb(n: int) -> int:
    return n // (1024 * 1024)


# ---- archives ------------------------------------------------------------------------------------


@rule("email.archive_bomb", "attachment")
def archive_bomb(ctx: Ctx) -> str | None:
    limits = scoring()["thresholds"]
    sizes = {p.path: max(p.size, 1) for p in ctx.scan.parts}
    for part, s in _archives(ctx):
        packed = sizes.get(part, 1)
        expands = s.total_size >= limits["archive_bomb_bytes"]
        if (expands and s.total_size / packed >= limits["archive_bomb_ratio"]) or (
            "decompressed_bytes" in s.limits
        ):
            return f"an archive that expands to at least {_mb(s.total_size)} MB from {packed} bytes"
    return None


@rule("email.archive_encrypted", "attachment")
def archive_encrypted(ctx: Ctx) -> str | None:
    n = sum(s.encrypted for _, s in _archives(ctx))
    return (
        f"{n} password-protected archive entries; their contents cannot be inspected" if n else None
    )


@rule("email.archive_traversal", "attachment")
def archive_traversal(ctx: Ctx) -> str | None:
    n = sum(s.traversal for _, s in _archives(ctx))
    return f"{n} archive entries with names that escape their folder" if n else None


@rule("email.archive_contents_dangerous", "attachment", MALICIOUS_FILE)
def archive_contents_dangerous(ctx: Ctx) -> str | None:
    dangerous = ext_list("dangerous_extensions")
    count, example = 0, ""
    for _, s in _archives(ctx):
        by_name = {ext: n for ext, n in s.exts.items() if ext in dangerous}
        by_content = sum(n for magic, n in s.magics.items() if magic in _RUNS_CODE_MAGIC)
        count += sum(by_name.values()) + by_content
        if by_name and not example:
            example = shown_ext(next(iter(by_name)))
    if not count:
        return None
    return f"{count} archive entries can run code, e.g. {example or 'executable content'}"


@rule("email.archive_double_extension", "attachment", DOUBLE_EXTENSION)
def archive_double_extension(ctx: Ctx) -> str | None:
    risky = ext_list("dangerous_extensions") | ext_list("macro_extensions")
    risky |= ext_list("html_extensions")
    for _, s in _archives(ctx):
        for inner, outer in s.double_pairs:
            if inner in DOCUMENT_LOOKING and outer in risky:
                return f"an archive entry pretends to be .{inner} but ends in {shown_ext(outer)}"
    return None


@rule("email.archive_contains_macro", "attachment", MALICIOUS_FILE)
def archive_contains_macro(ctx: Ctx) -> str | None:
    macro = ext_list("macro_extensions")
    n = sum(c for _, s in _archives(ctx) for ext, c in s.exts.items() if ext in macro)
    return f"{n} Office file(s) that can carry macros inside an archive" if n else None


@rule("email.archive_nested", "attachment")
def archive_nested(ctx: Ctx) -> str | None:
    depth = max((s.depth for _, s in _archives(ctx)), default=0)
    return f"archives nested {depth} levels deep" if depth >= 2 else None


# ---- PDF -----------------------------------------------------------------------------------------


@rule("email.pdf_javascript", "active_content", MALICIOUS_FILE)
def pdf_javascript(ctx: Ctx) -> str | None:
    n = sum(p.javascript for p in _pdfs(ctx))
    return f"{n} JavaScript action(s) in a PDF" if n else None


@rule("email.pdf_launch_action", "active_content", MALICIOUS_FILE)
def pdf_launch_action(ctx: Ctx) -> str | None:
    n = sum(p.launch for p in _pdfs(ctx))
    return f"{n} action(s) in a PDF that launch another program" if n else None


@rule("email.pdf_embedded_file", "attachment", ATTACHMENT)
def pdf_embedded_file(ctx: Ctx) -> str | None:
    n = sum(p.embedded_files for p in _pdfs(ctx))
    return f"{n} file(s) embedded in a PDF" if n else None


@rule("email.pdf_xfa", "active_content")
def pdf_xfa(ctx: Ctx) -> str | None:
    return (
        "a PDF with an XFA form (dynamic, scriptable content)"
        if any(p.xfa for p in _pdfs(ctx))
        else None
    )


@rule("email.pdf_encrypted", "structure")
def pdf_encrypted(ctx: Ctx) -> str | None:
    return (
        "an encrypted PDF; its contents cannot be inspected"
        if any(p.parse == "encrypted" for p in _pdfs(ctx))
        else None
    )


# ---- images and saved pages ----------------------------------------------------------------------


@rule("email.qr_code_link", "deception", LINK)
def qr_code_link(ctx: Ctx) -> str | None:
    """A QR code in an image: mail filters read text, a phone camera reads this."""
    hosts = [link.parsed.host for link in ctx.links if link.kind == "qr" and link.parsed]
    return f"{len(hosts)} QR code(s) in an image lead to {hosts[0] or 'a link'}" if hosts else None


@rule("email.image_bomb", "structure")
def image_bomb(ctx: Ctx) -> str | None:
    n = sum(i.bomb for i in _images(ctx))
    return f"{n} image(s) too large to decode safely" if n else None


@rule("email.html_smuggling", "active_content", HTML_SMUGGLING)
def html_smuggling(ctx: Ctx) -> str | None:
    h = ctx.scan.html
    builds = h.blob_apis > 0 and (h.base64_blobs > 0 or h.decoders > 0 or h.auto_saves > 0)
    if not (builds or h.data_downloads > 0):
        return None
    return (
        f"HTML that builds a file in the browser and saves it: {h.blob_apis} blob call(s), "
        f"{h.base64_blobs} encoded block(s), {h.data_downloads} data download link(s)"
    )


# ---- completeness --------------------------------------------------------------------------------


@rule("email.file_inspection_incomplete", "structure")
def file_inspection_incomplete(ctx: Ctx) -> str | None:
    reasons = sorted({f.failure for f in ctx.files if f.failure not in (None, "unsupported")})
    if not reasons:
        return None
    n = sum(1 for f in ctx.files if f.failure not in (None, "unsupported"))
    return f"{n} attachment(s) could not be fully inspected ({', '.join(str(r) for r in reasons)})"
