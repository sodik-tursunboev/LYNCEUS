"""Whole files through the real sandbox (op "inspect_bytes"): same findings as the in-process
scanner, and bomb shapes that must finish inside the limits with a stated outcome."""

import hashlib
import random
import sys
from typing import Any

import filehelp as fh
import pytest
from mailhelp import in_process_file

from core import sandbox
from core.contracts import VerdictState
from core.files.engine import FileAnalysis, analyze_file, run_inspect_bytes

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the sandbox is Windows-only")
EXE = b"MZ\x90\x00" + b"\x00" * 60
SMUGGLER = (
    b'<html><script>var b = new Blob([atob("QUJD")]); var a = document.createElement("a");'
    b'a.href = URL.createObjectURL(b); a.download = "x.zip"; a.click();</script></html>'
)


@pytest.fixture(autouse=True, scope="module")
def built() -> None:
    if not sandbox.available():
        pytest.fail("sandbox not built: run python tasks.py sandbox")


def judge(name: str, data: bytes, **kw: Any) -> FileAnalysis:
    return analyze_file(name, len(data), hashlib.sha256(data).hexdigest(), data, **kw)


def shape(a: FileAnalysis) -> tuple[Any, ...]:
    v = a.report.verdict
    return v.state, v.risk_score, [s.rule_id for s in v.signals], a.report.reason


FILES = {
    "disguised-exe": ("invoice.pdf.exe", EXE),
    "plain-text": ("notes.txt", b"just words"),
    "pdf-javascript": ("a.pdf", fh.PDF_JS),
    "zip-with-script": ("p.zip", fh.make_zip({"x.scr": b"x"})),
    "qr-image": ("c.png", fh.qr_png("https://paypal-login.test/login.php")),
    "smuggling-page": ("invoice.html", SMUGGLER),
    "encrypted-pdf": ("e.pdf", fh.encrypted_pdf()),
}


@pytest.mark.parametrize("key", sorted(FILES))
def test_the_sandbox_and_the_in_process_scanner_agree(key: str) -> None:
    name, data = FILES[key]
    real = judge(name, data)
    assert real.report.reason is None, real.report.reason
    assert shape(real) == shape(judge(name, data, run=in_process_file))


BOMBS = {
    "zip-bomb": ("b.zip", fh.zip_bomb(300)),
    "gzip-bomb": ("b.gz", fh.gzip_bomb(100)),
    "nested-zips": ("n.zip", fh.nested_zip(12)),
    "image-bomb": ("i.png", fh.png_declaring(60000, 60000)),
    "pdf-garbage": ("g.pdf", b"%PDF-1.7\n" + random.Random(5).randbytes(400_000)),
    "random-bytes": ("r.bin", random.Random(6).randbytes(2_000_000)),
    "truncated-png": ("t.png", fh.qr_png("https://x-y.test/")[:70]),
}


@pytest.mark.parametrize("key", sorted(BOMBS))
def test_bomb_shapes_finish_inside_the_limits_with_a_stated_outcome(key: str) -> None:
    name, data = BOMBS[key]
    result = run_inspect_bytes(data)
    assert result.ok, (key, result.reason)
    assert result.wall_seconds < 40 and result.peak_memory_mb < 1024, (key, result)
    a = judge(name, data)
    assert a.report.verdict.state is not VerdictState.ERROR and a.report.inspected is True


def test_the_bomb_rules_fire_on_the_real_findings() -> None:
    assert "email.archive_bomb" in {
        s.rule_id for s in judge(*BOMBS["zip-bomb"]).report.verdict.signals
    }
    assert "email.image_bomb" in {
        s.rule_id for s in judge(*BOMBS["image-bomb"]).report.verdict.signals
    }
    assert "email.html_smuggling" in {
        s.rule_id for s in judge(*FILES["smuggling-page"]).report.verdict.signals
    }
