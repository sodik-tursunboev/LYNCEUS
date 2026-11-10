"""The worker that runs INSIDE the sandbox. Standard library only; `core` is not importable here.

Protocol: stdin is a 4-byte big-endian header length, a JSON header, then the raw body. The answer
is one JSON document on stdout. The parent validates it and does not trust it.
"""

import hashlib
import json
import struct
import sys
from typing import Any


def read_request() -> tuple[dict[str, Any], bytes]:
    data = sys.stdin.buffer.read()
    (n,) = struct.unpack(">I", data[:4])
    header = json.loads(data[4 : 4 + n])
    if not isinstance(header, dict):
        raise ValueError("header must be an object")
    return header, data[4 + n :]


def handle(header: dict[str, Any], body: bytes) -> dict[str, Any]:
    op = header.get("op")
    if op == "ping":
        return {
            "ok": True,
            "python": sys.version.split()[0],
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    if op == "mime":
        import mailparse

        scan = mailparse.scan(body)
        return scan if "error" in scan else {"ok": True, "scan": scan}
    if op == "inspect":  # one attachment of a message, addressed by part path, in its own process
        import filescan
        import mailparse

        path = header.get("path")
        data = mailparse.part_bytes(body, path) if isinstance(path, str) else None
        if data is None:
            return {"error": "no_such_part"}
        return {"ok": True, "file": filescan.inspect_data(data)}
    if op == "inspect_bytes":  # a whole file: the body is the file
        import filescan

        return {"ok": True, **filescan.inspect_standalone(body)}
    if op == "macro_excerpt":  # the macro code of a file, or of one part of a message
        import filescan
        import mailparse

        path = header.get("path")
        data = (
            body
            if path is None
            else mailparse.part_bytes(body, path)
            if isinstance(path, str)
            else None
        )
        if data is None:
            return {"error": "no_such_part"}
        return {"ok": True, "excerpt": filescan.macro_excerpt(data)}
    return {"error": "unknown_op"}


def main() -> int:
    header, body = read_request()
    try:
        answer = handle(header, body)
    except MemoryError:
        answer = {"error": "memory"}
    except RecursionError:
        answer = {"error": "mime_too_deep"}
    sys.stdout.buffer.write(json.dumps(answer).encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0
