"""Helpers for message tests: build raw messages, run the guest parser here, fake the sandbox.

`in_process` stands in for the sandbox so rule and engine logic can be tested fast and anywhere. It
proves nothing about isolation: tests/sandbox and the `real_sandbox` tests do that.
"""

import json
import os
from collections.abc import Sequence
from email.message import EmailMessage

import filescan
import mailparse

from core import sandbox
from core.email.engine import EmailAnalysis, analyze_message
from core.email.models import MessageScan

HOSTS_SEALED = os.name == "nt"  # stored site names are sealed with DPAPI (ADR-007): Windows only
Attachment = tuple[str, bytes, str]  # file name, content, content type
PHISH_LINK = '<a href="https://evil-site.test/x">https://www.paypal.com/login</a>'


def eml(
    *,
    sender: str = "Alice <alice@sender.test>",
    to: str = "bob@rcpt.test",
    subject: str = "Hello",
    text: str | None = "Hi Bob, lunch on Friday?",
    html: str | None = None,
    attachments: Sequence[Attachment] = (),
    extra_headers: Sequence[tuple[str, str]] = (),
) -> bytes:
    """A well-formed message; `extra_headers` are written raw, so duplicates are possible."""
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 02 Nov 2026 10:00:00 +0000"
    msg["Message-ID"] = "<test@sender.test>"
    if text is not None:
        msg.set_content(text)
    if html is not None:
        if text is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    for name, data, ctype in attachments:
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    extra = "".join(f"{k}: {v}\r\n" for k, v in extra_headers).encode("utf-8")
    return extra + msg.as_bytes()


def multipart(parts: int) -> bytes:
    """A flat multipart/mixed message with `parts` tiny text parts."""
    body = "".join(f"--bb\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n" for i in range(parts))
    head = 'From: a@x.test\r\nContent-Type: multipart/mixed; boundary="bb"\r\n\r\n'
    return (head + body + "--bb--\r\n").encode()


def nested(depth: int) -> bytes:
    """multipart inside multipart inside ... `depth` levels deep."""
    body = "leaf"
    for i in reversed(range(depth)):
        head = f'Content-Type: multipart/mixed; boundary="b{i}"\r\n\r\n'
        body = f"{head}--b{i}\r\n{body}\r\n--b{i}--\r\n"
    return ("From: a@x.test\r\n" + body).encode()


def ok_result(output: bytes, reason: str = "ok") -> sandbox.Result:
    return sandbox.Result(
        ok=reason == "ok", output=output, reason=reason, exit_code=0,
        cpu_seconds=0.0, peak_memory_mb=0.0, wall_seconds=0.0, pid=0,
    )  # fmt: skip


def in_process(raw: bytes) -> sandbox.Result:
    return ok_result(json.dumps({"ok": True, "scan": mailparse.scan(raw)}).encode())


def in_process_inspect(raw: bytes, path: str) -> sandbox.Result:
    """The same, for one attachment (op "inspect")."""
    data = mailparse.part_bytes(raw, path)
    reply = (
        {"error": "no_such_part"}
        if data is None
        else {"ok": True, "file": filescan.inspect_data(data)}
    )
    return ok_result(json.dumps(reply).encode())


def in_process_file(data: bytes) -> sandbox.Result:
    """The same, for a whole file (op "inspect_bytes")."""
    return ok_result(json.dumps({"ok": True, **filescan.inspect_standalone(data)}).encode())


def parsed(raw: bytes) -> MessageScan:
    """What the host would accept from the worker for `raw` (validates the guest's output)."""
    return MessageScan.model_validate(mailparse.scan(raw))


def analyze(raw: bytes) -> EmailAnalysis:
    return analyze_message(raw, run=in_process, inspect_run=in_process_inspect)


def fired(raw: bytes) -> set[str]:
    return {s.rule_id for s in analyze(raw).report.verdict.signals}
