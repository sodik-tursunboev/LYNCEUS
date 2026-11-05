"""The message pipeline through the real sandbox (Windows AppContainer + Job Object).

Parity: the sandbox gives the same verdicts as the in-process parser, so the fast tests elsewhere
mean something. Hostile shapes: every one finishes inside the limits with a stated outcome.
Fails loudly if the sandbox is not built: skipping would hide a missing security control.
"""

import random
import sys
from pathlib import Path

import pytest
from mailhelp import PHISH_LINK, analyze, eml, multipart, nested

from core import sandbox
from core.contracts import VerdictState
from core.email.engine import MAX_MESSAGE_BYTES, EmailAnalysis, analyze_message, run_sandbox
from core.email.models import WorkerReply

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
