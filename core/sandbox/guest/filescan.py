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
    if magic in ("html", "svg"):
        import htmlscan

        budget = htmlscan.Budget()
        text = data[: MAX_HTML_CHARS * 4].decode("utf-8", "replace")[:MAX_HTML_CHARS]
        htmlscan.scan_html(text, "1", budget)
        html = dict(budget.stats)
    return {"magic": magic, "file": inspect_data(data), "html": html}


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
