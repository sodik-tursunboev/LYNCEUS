"""The message pipeline through the real sandbox (Windows AppContainer + Job Object).

Parity: the sandbox gives the same verdicts as the in-process parser, so the fast tests elsewhere
mean something. Hostile shapes: every one finishes inside the limits with a stated outcome.
Fails loudly if the sandbox is not built: skipping would hide a missing security control.
"""

import random
import sys
from pathlib import Path

import filehelp as fh
import pytest
from mailhelp import PHISH_LINK, analyze, eml, multipart, nested

from core import sandbox
from core.contracts import VerdictState
from core.email.engine import (
    MAX_MESSAGE_BYTES,
    EmailAnalysis,
    analyze_message,
    run_inspect,
    run_sandbox,
)
from core.email.models import FileReply, WorkerReply

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the sandbox is Windows-only")
GUEST = Path(sandbox.__file__).parent / "guest"
CORPUS = Path(__file__).parents[2] / "corpus" / "mail"


@pytest.fixture(autouse=True, scope="module")
def built() -> None:
    if not sandbox.available():
        pytest.fail("sandbox not built: run python tasks.py sandbox")


def shape(a: EmailAnalysis) -> tuple[object, ...]:
    v = a.report.verdict
    return v.state, v.risk_score, [s.rule_id for s in v.signals], a.report.reason


def test_the_sandbox_copy_of_the_parser_is_the_current_source() -> None:
    for source in sorted(GUEST.glob("*.py")):
        copy = sandbox.APP / source.name
        assert copy.exists(), f"{source.name} missing from the sandbox: run python tasks.py sandbox"
        assert copy.read_bytes() == source.read_bytes(), (
            f"{source.name} changed since the sandbox was built: run python tasks.py sandbox"
        )


@pytest.mark.parametrize(
    "raw",
    [
        eml(),
        eml(sender='"PayPal Support" <help@paypal-login.test>', subject="Urgent", html=PHISH_LINK),
        eml(
            attachments=[
                ("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 60, "application/octet-stream")
            ]
        ),
        (CORPUS / "m-001.eml").read_bytes(),
    ],
    ids=["clean", "phish", "attachment", "corpus-m-001"],
)
def test_the_sandbox_and_the_in_process_parser_agree(raw: bytes) -> None:
    real = analyze_message(raw)
    assert real.report.reason is None, real.report.reason
    assert shape(real) == shape(analyze(raw))


def test_the_worker_reply_is_what_the_host_validates() -> None:
    result = run_sandbox(eml())
    assert result.ok and result.reason == "ok"
    assert WorkerReply.model_validate_json(result.output).scan is not None


# ---- hostile shapes, in the real sandbox ---------------------------------------------------------


def flat(size: int) -> bytes:
    return b"From: a@x.test\r\nSubject: big\r\n\r\n" + b"A" * size


def tags(count: int) -> bytes:
    return eml(text=None, html="<b>" * count)


def noise(size: int) -> bytes:
    return random.Random(11).randbytes(size)


HOSTILE = {
    "ten-thousand-parts": multipart(10_000),
    "deep-nesting": nested(2_000),
    "one-giant-line": flat(MAX_MESSAGE_BYTES - 1024),
    "a-million-tags": tags(3_000_000),
    "random-bytes": noise(2_000_000),
    "header-flood": ("".join(f"X-{i}: v\r\n" for i in range(60_000)) + "\r\nbody").encode(),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_shapes_finish_inside_the_limits_with_a_stated_outcome(name: str) -> None:
    raw = HOSTILE[name]
    assert len(raw) <= MAX_MESSAGE_BYTES
    result = run_sandbox(raw)
    a = analyze_message(raw)
    assert result.wall_seconds < 20 and result.peak_memory_mb < 512, (name, result)
    assert a.report.verdict.state is not VerdictState.ERROR, (name, a.report.reason)
    assert a.report.verdict.state is not VerdictState.BENIGN


def test_a_message_over_the_cap_never_starts_a_sandbox() -> None:
    a = analyze_message(b"a" * (MAX_MESSAGE_BYTES + 1))
    assert (a.report.verdict.state, a.report.reason) == (VerdictState.UNKNOWN, "too_large")


# ---- attachments, in the real sandbox -----------------------------------------------------------

ATTACHED = {
    "zip-with-exe": (
        "pack.zip", fh.make_zip({"setup.scr": b"MZ\x90\x00", "a.txt": b"hi"}), "application/zip",
    ),
    "pdf-javascript": ("a.pdf", fh.PDF_JS, "application/pdf"),
    "pdf-links": (
        "l.pdf", fh.pdf_with_uris("https://paypal-login.test/login.php"), "application/pdf",
    ),
    "qr-image": ("code.png", fh.qr_png("https://paypal-login.test/login.php"), "image/png"),
    "encrypted-pdf": ("e.pdf", fh.encrypted_pdf(), "application/pdf"),
}  # fmt: skip


def attached(name: str) -> bytes:
    return eml(attachments=[ATTACHED[name]])


def test_the_pinned_parser_libraries_are_installed_in_the_sandbox() -> None:
    site = sandbox.RUNTIME / "Lib" / "site-packages"
    for package in ("pikepdf", "PIL", "cv2", "numpy", "lxml"):
        assert (site / package).is_dir(), f"{package} missing: run python tasks.py sandbox"


@pytest.mark.parametrize("name", sorted(ATTACHED))
def test_attachments_give_the_same_findings_in_the_sandbox_and_in_process(name: str) -> None:
    raw = attached(name)
    real, local = analyze_message(raw), analyze(raw)
    assert real.report.reason is None and all(f.status == "ok" for f in real.report.files)
    assert shape(real) == shape(local)
    assert [(f.kind, f.facts) for f in real.report.files] == [
        (f.kind, f.facts) for f in local.report.files
    ]


def test_a_file_reply_from_the_real_worker_validates() -> None:
    result = run_inspect(attached("pdf-javascript"), "1.2")
    assert result.ok
    assert FileReply.model_validate_json(result.output).file is not None


def test_an_unknown_part_is_a_stated_error_not_a_crash() -> None:
    result = run_inspect(eml(), "1.9")
    assert result.ok and FileReply.model_validate_json(result.output).error == "no_such_part"


BOMBS = {
    "zip-bomb-300mib": ("b.zip", fh.zip_bomb(300), "application/zip"),
    "gzip-bomb-100mib": ("b.gz", fh.gzip_bomb(100), "application/gzip"),
    "nested-zips": ("n.zip", fh.nested_zip(12), "application/zip"),
    "many-entries": ("m.zip", fh.many_entries_zip(5000), "application/zip"),
    "image-bomb": ("i.png", fh.png_declaring(60000, 60000), "image/png"),
    "pdf-150k-objects": ("o.pdf", fh.pdf_with_objects(150_000), "application/pdf"),
    "pdf-garbage": (
        "g.pdf", b"%PDF-1.7\n" + random.Random(3).randbytes(500_000), "application/pdf",
    ),
    "truncated-png": ("t.png", fh.qr_png("https://x-y.test/")[:80], "image/png"),
}  # fmt: skip


@pytest.mark.parametrize("name", sorted(BOMBS))
def test_bombs_are_reported_inside_the_limits_and_never_crash_the_sandbox(name: str) -> None:
    raw = eml(attachments=[BOMBS[name]])
    result = run_inspect(raw, "1.2")
    assert result.ok, (name, result.reason)
    assert result.wall_seconds < 40 and result.peak_memory_mb < 1024, (name, result)
    a = analyze_message(raw)
    assert a.report.verdict.state is not VerdictState.ERROR
    assert a.report.files and a.report.files[0].status == "ok", (name, a.report.files)


def test_the_bomb_rules_fire_on_the_real_findings() -> None:
    zip_hit = analyze_message(eml(attachments=[BOMBS["zip-bomb-300mib"]]))
    assert "email.archive_bomb" in {s.rule_id for s in zip_hit.report.verdict.signals}
    image_hit = analyze_message(eml(attachments=[BOMBS["image-bomb"]]))
    assert "email.image_bomb" in {s.rule_id for s in image_hit.report.verdict.signals}
