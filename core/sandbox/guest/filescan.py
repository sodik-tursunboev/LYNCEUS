"""Dispatch one attachment to its scanner by what it IS (magic number), not what it is called.

Each scanner imports its own libraries when needed, so an archive scan never loads the PDF or image
libraries. Runs inside the sandbox; one attachment per process, so a crash costs one file.
"""

from typing import Any

from filetype import detect_magic

IMAGES = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}
ARCHIVES = {"zip", "gz", "bz2", "xz", "tar"}


def inspect_standalone(data: bytes) -> dict[str, Any]:
    """A whole file (not a message part): its real type, the scan of its contents and, for a web
    page, the same smuggling indicators as an HTML attachment."""
    from limits import MAX_HTML_CHARS

    magic: str | None = detect_magic(data[:600])
    html: dict[str, Any] | None = None
    active: list[str] = []
    if magic in ("html", "svg"):
        import htmlscan

        budget = htmlscan.Budget()
        text = data[: MAX_HTML_CHARS * 4].decode("utf-8", "replace")[:MAX_HTML_CHARS]
        htmlscan.scan_html(text, "1", budget)
        html = dict(budget.stats)
        if magic == "svg":
            active = htmlscan.svg_active(text)  # H1 C2
    return {"magic": magic, "file": inspect_data(data), "html": html, "active": active}


def macro_excerpt(data: bytes) -> str:
    """The macro code of one file as bounded plain text (the old Office format, or an Office zip
    holding a macro project and/or Excel 4.0 sheets), for the local model. Empty when there is no
    macro. Never returned to a caller that stores or logs it: the host passes it straight on."""
    import io
    import zipfile

    import olescan
    import vbaanalyze
    import xlmscan
    from limits import MAX_MEMBER_BYTES

    magic = detect_magic(data[:600])
    sources: list[str] = []
    sheets: list[str] = []
    if magic == "ole":
        sources = olescan.macro_sources(data)
    elif magic == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist()[:2000]:
                    low = info.filename.replace("\\", "/").lower()
                    if info.file_size > MAX_MEMBER_BYTES or not (
                        low.endswith("vbaproject.bin") or low.startswith("xl/macrosheets/")
                    ):
                        continue
                    with zf.open(info) as f:
                        body = f.read(MAX_MEMBER_BYTES + 1)
                    if low.endswith("vbaproject.bin"):
                        sources += olescan.macro_sources(body)
                    else:
                        sheets.append(xlmscan.excerpt(body))
        except (zipfile.BadZipFile, ValueError, OSError, RuntimeError):
            return ""
    text = vbaanalyze.excerpt(sources, 9000) if sources else ""
    if sheets:
        text += "\n' --- Excel 4.0 macro sheet formulas ---\n" + "\n".join(sheets)
    return text.strip()[:12_000]


def inspect_data(data: bytes) -> dict[str, Any]:
    magic = detect_magic(data[:600])
    if magic in ARCHIVES:
        import archives

        archive: dict[str, Any] = archives.scan_archive(data)
        return archive
    if magic == "pdf":
        import pdfscan

        document: dict[str, Any] = pdfscan.scan_pdf(data)
        return document
    if magic in IMAGES:
        import imagescan

        picture: dict[str, Any] = imagescan.scan_image(data)
        return picture
    import contentscan  # scripts, shortcuts, executables, Office and RTF files, saved pages

    inside: dict[str, Any] = contentscan.scan_content(data, magic)
    return inside
