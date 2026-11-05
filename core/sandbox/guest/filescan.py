"""Dispatch one attachment to its scanner by what it IS (magic number), not what it is called.

Each scanner imports its own libraries when needed, so an archive scan never loads the PDF or image
libraries. Runs inside the sandbox; one attachment per process, so a crash costs one file.
"""

from typing import Any

from filetype import detect_magic

IMAGES = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}
ARCHIVES = {"zip", "gz", "bz2", "xz", "tar"}


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
    return {"kind": "none"}
