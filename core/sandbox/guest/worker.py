"""The worker that runs INSIDE the sandbox. Standard library only; `core` is not importable here.

Protocol: stdin is a 4-byte big-endian header length, a JSON header, then the raw body. The answer
is one JSON document on stdout. The parent validates it and does not trust it.
"""

import hashlib
import json
import struct
import sys


def read_request() -> tuple[dict[str, object], bytes]:
    data = sys.stdin.buffer.read()
    (n,) = struct.unpack(">I", data[:4])
    header = json.loads(data[4 : 4 + n])
    if not isinstance(header, dict):
        raise ValueError("header must be an object")
    return header, data[4 + n :]


def handle(header: dict[str, object], body: bytes) -> dict[str, object]:
    op = header.get("op")
    if op == "ping":
        return {
            "ok": True,
            "python": sys.version.split()[0],
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    return {"error": "unknown_op"}


def main() -> int:
    header, body = read_request()
    sys.stdout.buffer.write(json.dumps(handle(header, body)).encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0
