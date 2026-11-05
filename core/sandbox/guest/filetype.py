"""File type by content (magic numbers), never by name or declared type. Standard library only."""


def detect_magic(data: bytes) -> str | None:
    head = data[:16]
    table = (
        (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"Rar!\x1a\x07", "rar"),
        (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gz"), (b"BZh", "bz2"),
        (b"\xfd7zXZ\x00", "xz"), (b"MZ", "exe"),
        (b"\x7fELF", "elf"), (b"\xd0\xcf\x11\xe0", "ole"), (b"{\\rtf", "rtf"), (b"\x89PNG", "png"),
        (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"BM", "bmp"), (b"II*\x00", "tiff"),
        (b"MM\x00*", "tiff"), (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    )  # fmt: skip
    for sig, name in table:
        if head.startswith(sig):
            return name
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data[257:262] == b"ustar":
        return "tar"
    text = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta")):
        return "html"
    if b"<svg" in text:
        return "svg"
    return None
