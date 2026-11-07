"""Structured JSON logging with redaction (ADR-006). Fails closed: when unsure, redact.

URLs are never logged whole: only `url[host=<host> sha=<12 hex of the full URL>]`, which keeps
events correlatable without leaking paths, query strings or userinfo. The hash of a guessable
URL can be brute-forced; acceptable for a local log, not for export.
"""

import hashlib
import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import IO, Any
from urllib.parse import urlsplit

REDACTED = "[REDACTED]"

_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
# The key may carry a prefix (refresh_token, client_secret, LYNCEUS_API_TOKEN, POSTGRES_PASSWORD)
# and may be quoted (JSON): a word boundary alone would let `refresh_token=...` through.
_KV = re.compile(
    r"(?i)\b([\w.\-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|authorization))"
    r"(\"?\s*[=:]\s*\"?)([^\s\",;&]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}")
# Substring match on purpose: over-redacting `passed` is cheaper than leaking `passwd`.
_SENSITIVE_KEY = re.compile(
    r"(?i)pass|pwd|secret|token|api[_-]?key|authoriz|cookie|credential|session|private[_-]?key"
    r"|database_url|dsn"
)


def _url_stub(m: re.Match[str]) -> str:
    url = m.group(0)
    try:
        host = urlsplit(url).hostname or "?"
    except ValueError:
        host = "?"
    return f"url[host={host} sha={hashlib.sha256(url.encode()).hexdigest()[:12]}]"


def redact_text(text: str) -> str:
    text = _URL.sub(_url_stub, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact_value(value: Any, key: str = "") -> Any:
    if key and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(v) for v in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


_STANDARD = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        for k, v in record.__dict__.items():
            if k not in _STANDARD:
                out[k] = redact_value(v, k)
        if record.exc_info:
            out["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(out, default=str)


class LynceusHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """Marker subclass so configure() can replace its own handler without touching others."""


def configure(level: str = "INFO", stream: IO[str] | None = None) -> None:
    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if not isinstance(h, LynceusHandler)]
    handler = LynceusHandler(stream or sys.stderr)
    handler.setFormatter(RedactingJsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
