"""Attachment fixtures, generated at test time and kept small: archives, bombs, PDFs and images.

Nothing here is a real exploit. A "bomb" is a few kilobytes that DECLARES a huge size; the scanners
under test must report it without expanding it. PDFs are hand-written text (qpdf rebuilds the
cross-reference table), so the tests do not depend on the library that reads them to write them.
"""

import bz2
import gzip
import io
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from functools import cache

MiB = 1024 * 1024


def make_zip(entries: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def mark_encrypted(data: bytes) -> bytes:
    """Set the 'encrypted' flag on every entry (the bytes stay as they were: it is only a flag)."""
    out = bytearray(data)
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = out.find(signature)
        while at != -1:
            out[at + offset] |= 1
            at = out.find(signature, at + 4)
    return bytes(out)


@cache
def zip_bomb(total_mib: int = 300) -> bytes:
    """One entry of zeros that declares `total_mib` MiB: a few hundred KB on the wire."""
    buf = io.BytesIO()
    chunk = b"\x00" * MiB
    with (
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf,
        zf.open("big.bin", "w", force_zip64=True) as f,
    ):
        for _ in range(total_mib):
            f.write(chunk)
    return buf.getvalue()


def nested_zip(depth: int, leaf: bytes = b"hello") -> bytes:
    data = make_zip({"leaf.txt": leaf})
    for i in range(depth):
        data = make_zip({f"level{i}.zip": data})
    return data


def many_entries_zip(count: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for i in range(count):
            zf.writestr(f"f{i}.txt", b"")
    return buf.getvalue()


@cache
def gzip_bomb(mib: int = 100) -> bytes:
    return gzip.compress(b"\x00" * (mib * MiB), compresslevel=9)


def bz2_of(data: bytes) -> bytes:
    return bz2.compress(data)


def make_tar(entries: Mapping[str, bytes], symlinks: Mapping[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


# ---- PDF -----------------------------------------------------------------------------------------


def make_pdf(catalog: str = "", objects: Sequence[str] = ()) -> bytes:
    """A one-page PDF as text plus extra objects numbered from 4. No xref: qpdf rebuilds it."""
    lines = [
        "%PDF-1.7",
        "1 0 obj", f"<< /Type /Catalog /Pages 2 0 R {catalog} >>", "endobj",
        "2 0 obj", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "endobj",
        "3 0 obj", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>", "endobj",
    ]  # fmt: skip
    for number, body in enumerate(objects, start=4):
        lines += [f"{number} 0 obj", body, "endobj"]
    lines += ["trailer", "<< /Root 1 0 R >>", "%%EOF"]
    return "\n".join(lines).encode("latin-1")


PDF_JS = make_pdf("/OpenAction 4 0 R", ["<< /S /JavaScript /JS (app.alert\\(1\\)) >>"])
PDF_JS_OBFUSCATED = make_pdf("/OpenAction 4 0 R", ["<< /S /J#61vaScr#69pt /JS (x) >>"])
PDF_LAUNCH = make_pdf("/OpenAction 4 0 R", ["<< /S /Launch /F (cmd.exe) >>"])
PDF_EMBEDDED = make_pdf("", ["<< /Type /EmbeddedFile /Length 5 >>\nstream\nhello\nendstream"])
PDF_PLAIN = make_pdf()


def pdf_with_uris(*uris: str) -> bytes:
    links = [
        f"<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /A << /S /URI /URI ({u}) >> >>"
        for u in uris
    ]
    return make_pdf("", links)


def encrypted_pdf() -> bytes:
    import pikepdf

    buf = io.BytesIO()
    pdf = pikepdf.new()
    pdf.add_blank_page()
    pdf.save(buf, encryption=pikepdf.Encryption(owner="owner-pw", user="user-pw"))
    return buf.getvalue()


def pdf_with_objects(count: int) -> bytes:
    return make_pdf("", [f"<< /K {i} >>" for i in range(count)])


# ---- images --------------------------------------------------------------------------------------


def qr_png(text: str, scale: int = 8) -> bytes:
    """A PNG of a QR code, built with OpenCV's encoder (a sandbox-only library, used as a tool)."""
    import cv2

    code = cv2.QRCodeEncoder.create().encode(text)
    big = cv2.resize(code, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    padded = cv2.copyMakeBorder(big, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, png = cv2.imencode(".png", padded)
    assert ok
    return png.tobytes()


def blank_png(width: int = 64, height: int = 64) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("L", (width, height), 255).save(buf, "PNG")
    return buf.getvalue()


def png_declaring(width: int, height: int) -> bytes:
    """A PNG whose header claims width x height with almost no data: a decompression-bomb shape."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(kind + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit grayscale
    return (
        b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00")) + chunk(b"IEND", b"")
    )  # fmt: skip
