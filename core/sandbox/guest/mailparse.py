"""MIME message scanner. Standard library only; runs inside the sandbox on hostile input.

It extracts facts and never judges them: the host applies the rules. Nothing is executed, written
or fetched. Every cap in `limits.py` is reported in `limits_hit` instead of failing the scan, and
the walk is iterative so a deeply nested message cannot exhaust the stack.
"""

import email
import email.policy
import hashlib
import re
from email.header import decode_header, make_header
from email.utils import getaddresses
from typing import Any

import htmlscan
import textscan
from filetype import detect_magic
from limits import (
    MAX_ADDRS,
    MAX_DECODED_TOTAL,
    MAX_DEFECTS,
    MAX_DEPTH,
    MAX_EXCERPT,
    MAX_FILENAME,
    MAX_HEADER_CHARS,
    MAX_HEADERS,
    MAX_HTML_CHARS,
    MAX_LINK_URL,
    MAX_PART_BYTES,
    MAX_PARTS,
    MAX_SUBJECT,
)

_BIDI = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_AUTH_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}
_BAD_CHARSETS = {
    "unicode_escape",
    "unicode-escape",
    "raw_unicode_escape",
    "idna",
    "punycode",
    "undefined",
}
_HTML_TYPES = {"text/html", "application/xhtml+xml"}


def _words(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001
        return value


def _headers(msg: Any, name: str) -> list[str]:
    return [str(v)[:MAX_HEADER_CHARS] for v in (msg.get_all(name) or [])][:MAX_ADDRS]


def _addresses(values: list[str]) -> list[dict[str, str]]:
    out = []
    for display, addr in getaddresses(values)[:MAX_ADDRS]:
        addr = addr.strip()
        if "@" in addr:
            domain = addr.rpartition("@")[2].strip(" >").lower()
            out.append({"name": _words(display)[:200], "addr": addr[:320], "domain": domain[:255]})
    return out


def _auth(msg: Any) -> dict[str, Any]:
    """The topmost Authentication-Results header: whoever added it, which we cannot verify."""
    values = _headers(msg, "Authentication-Results")
    auth: dict[str, Any] = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "authserv": None,
        "count": len(values),
    }
    if values:
        auth["authserv"] = values[0].split(";", 1)[0].strip()[:255] or None
        for method, result in _AUTH.findall(values[0]):
            if auth[method.lower()] is None:
                auth[method.lower()] = (
                    result.lower() if result.lower() in _AUTH_RESULTS else "unknown"
                )
    return auth


def _filename(node: Any) -> tuple[str | None, list[str]]:
    flags: list[str] = []
    try:
        raw = node.get_filename()
    except Exception:  # noqa: BLE001
        raw = None
    if not raw:
        return None, flags
    name = _words(str(raw))
    if _BIDI.search(name):
        flags.append("bidi_filename")
        name = _BIDI.sub("?", name)
    if _CONTROL.search(name):
        flags.append("control_chars_in_filename")
        name = _CONTROL.sub("?", name)
    if "/" in name or "\\" in name:
        flags.append("path_in_filename")
        name = re.split(r"[\\/]", name)[-1]
    if len(name) > MAX_FILENAME:
        flags.append("long_filename")
        name = name[:MAX_FILENAME]
    return name or None, flags


def _text(data: bytes, charset: str | None) -> str:
    if charset and charset.lower() not in _BAD_CHARSETS:
        try:
            return data.decode(charset, errors="replace")
        except LookupError:
            pass
    return data.decode("utf-8", errors="replace")


def _message_headers(msg: Any, hit: set[str]) -> dict[str, Any]:
    if len(msg.keys()) > MAX_HEADERS:
        hit.add("headers")
    subject = _words(_headers(msg, "Subject")[0]) if msg.get_all("Subject") else ""
    to_count = len(getaddresses(_headers(msg, "To") + _headers(msg, "Cc")))
    return {
        "from": _addresses(_headers(msg, "From")),
        "from_count": len(msg.get_all("From") or []),
        "reply_to": _addresses(_headers(msg, "Reply-To")),
        "return_path": _addresses(_headers(msg, "Return-Path")),
        "sender": _addresses(_headers(msg, "Sender")),
        "recipient_count": min(to_count, 1000),
        "subject": subject[:MAX_SUBJECT],
        "received_count": min(len(msg.get_all("Received") or []), 1000),
        "auth": _auth(msg),
        "list_unsubscribe": bool(msg.get("List-Unsubscribe")),
        "date_present": bool(msg.get("Date")),
    }


_PATH = re.compile(r"^1(?:\.[1-9][0-9]{0,3}){0,20}$")


def part_bytes(raw: bytes, path: str) -> bytes | None:
    """The decoded bytes of one leaf part, addressed by the paths `scan` reports (None: no such)."""
    if not _PATH.match(path):
        return None
    node: Any = email.message_from_bytes(raw, policy=email.policy.compat32)
    for index in (int(i) for i in path.split(".")[1:]):
        children = node.get_payload()
        if not node.is_multipart() or not isinstance(children, list) or index > len(children):
            return None
        node = children[index - 1]
    if node.is_multipart():
        return None
    try:
        data = node.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return b""
    return data[:MAX_PART_BYTES] if isinstance(data, bytes) else b""


def scan(raw: bytes) -> dict[str, Any]:
    hit: set[str] = set()
    defects: set[str] = set()
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except RecursionError:
        return {"error": "mime_too_deep"}
    budget = htmlscan.Budget()
    parts: list[dict[str, Any]] = []
    decoded_total = 0
    visited = 0
    stack: list[tuple[Any, str, int]] = [(msg, "1", 0)]
    while stack:
        node, path, depth = stack.pop()
        visited += 1
        if visited > MAX_PARTS:
            hit.add("parts")
            break
        defects.update(type(d).__name__ for d in node.defects)
        if depth > MAX_DEPTH:
            hit.add("depth")
            continue
        if node.is_multipart():
            children = node.get_payload()
            if isinstance(children, list):
                for i in range(len(children), 0, -1):
                    stack.append((children[i - 1], f"{path}.{i}", depth + 1))
            continue

        ctype = node.get_content_type()
        disposition = node.get_content_disposition()
        filename, flags = _filename(node)
        attachment = (
            disposition == "attachment"
            or bool(filename)
            or node.get_content_maintype() not in ("text", "multipart", "message")
        )
        try:
            data = node.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            data, flags = b"", [*flags, "decode_error"]
        if not isinstance(data, bytes):
            data = b""
        if len(data) > MAX_PART_BYTES:
            hit.add("part_bytes")
            data = data[:MAX_PART_BYTES]
        decoded_total += len(data)
        if decoded_total > MAX_DECODED_TOTAL:
            hit.add("decoded_bytes")
            data = b""
        magic = detect_magic(data)

        if ctype in _HTML_TYPES or magic in ("html", "svg"):
            htmlscan.scan_html(
                _text(data, node.get_content_charset())[:MAX_HTML_CHARS], path, budget
            )
        elif ctype == "text/plain":
            text = _text(data, node.get_content_charset())
            urls, cut = textscan.find_urls(text, 200, MAX_LINK_URL)
            for url in urls:
                budget.add_link(path, "text", url, [])
            if cut:
                hit.add("text_urls")
            budget.add_text(" ".join(text[:MAX_EXCERPT].split()))

        parts.append(
            {
                "path": path,
                "ctype": ctype[:100],
                "charset": (node.get_content_charset() or None),
                "disposition": disposition,
                "filename": filename,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "magic": magic,
                "attachment": attachment,
                "flags": flags,
            }
        )
    headers = _message_headers(msg, hit)  # before limits_hit: it can add "headers" to it
    return {
        "v": 1,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "limits_hit": sorted(hit | budget.hit),
        "defects": sorted(defects)[:MAX_DEFECTS],
        "headers": headers,
        "parts": parts,
        "links": budget.links,
        "base": budget.base,
        "html": budget.stats,
        "excerpt": " ".join(budget.excerpt)[:MAX_EXCERPT],
    }
