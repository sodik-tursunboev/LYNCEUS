"""Image triage: size check before decoding, then QR codes. Runs in the sandbox on hostile input.

Pillow opens only the formats listed here (no EPS, which could call Ghostscript; nothing exotic),
reads the header first, and refuses to decode an image over MAX_PIXELS. QR payloads are attacker
text: they are returned as strings and analysed offline by the host, never opened.
"""

import io
import re
import warnings
from typing import Any

from limits import MAX_PIXELS, MAX_QR, MAX_QR_CHARS

_FORMATS = ["PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP"]
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _qr(gray: Any) -> list[str]:
    import cv2

    height, width = gray.shape[:2]
    big = max(height, width)
    base = gray
    if big > 2000:
        base = cv2.resize(gray, None, fx=2000 / big, fy=2000 / big, interpolation=cv2.INTER_AREA)
    attempts = [base]
    if big < 400:
        attempts.append(cv2.resize(base, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST))
    attempts.append(cv2.bitwise_not(base))  # light-on-dark codes
    detector = cv2.QRCodeDetector()
    for image in attempts:
        padded = cv2.copyMakeBorder(image, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=255)
        try:
            ok, decoded, _points, _straight = detector.detectAndDecodeMulti(padded)
        except cv2.error:
            continue
        found = [s for s in decoded if isinstance(s, str) and s] if ok else []
        if found:
            return found
    return []


def scan_image(data: bytes) -> dict[str, Any]:
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # a warning at 1x, an error at 2x; both end the scan
    out: dict[str, Any] = {
        "kind": "image", "format": None, "width": 0, "height": 0, "parse": "ok", "bomb": False,
        "qr": [],
    }  # fmt: skip
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(io.BytesIO(data), formats=_FORMATS)
        except (Image.DecompressionBombError, Image.DecompressionBombWarning):
            out.update(parse="bomb", bomb=True)
            return out
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001
            out["parse"] = "failed"
            return out
        out.update(format=(image.format or "").lower(), width=image.width, height=image.height)
        if image.width * image.height > MAX_PIXELS:
            out.update(parse="bomb", bomb=True)
            return out
        try:
            import numpy as np

            gray = np.asarray(image.convert("L"))
            payloads = _qr(gray)
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001  (a truncated or corrupt image)
            out["parse"] = "failed"
            return out
    seen: dict[str, None] = {}
    for payload in payloads:
        text = _CONTROL.sub("", payload).strip()[:MAX_QR_CHARS]
        if text and len(seen) < MAX_QR:
            seen[text] = None
    out["qr"] = list(seen)
    return out
