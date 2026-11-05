"""python -m core.cli analyze-eml <path>: offline, reads one file, prints the verdict."""

import json
from pathlib import Path

import pytest
from mailhelp import PHISH_LINK, eml, in_process

from core import sandbox
from core.cli import main
from core.contracts import Verdict
from core.email import engine
from core.email.engine import MAX_MESSAGE_BYTES


@pytest.fixture(autouse=True)
def fake_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "run_sandbox", in_process)


def run(capsys: pytest.CaptureFixture[str], path: Path, *args: str) -> tuple[int, str, str]:
    code = main(["analyze-eml", str(path), *args])
    out, err = capsys.readouterr()
    return code, out, err


def write(tmp_path: Path, raw: bytes) -> Path:
    path = tmp_path / "m.eml"
    path.write_bytes(raw)
    return path


def test_text_output_names_the_verdict_the_message_and_the_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = eml(sender='"PayPal Support" <help@paypal-login.test>', subject="Urgent", html=PHISH_LINK)
    code, out, _ = run(capsys, write(tmp_path, raw))
    assert code == 0 and out.split()[0] in ("SUSPICIOUS", "MALICIOUS")
    assert "email.display_name_brand" in out and "applied none" in out
    assert "attachments" in out and "link [a]" in out


def test_json_output_is_the_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, write(tmp_path, eml(html=PHISH_LINK)), "--json")
    body = json.loads(out)
    Verdict.model_validate(body["verdict"])
    assert code == 0 and body["summary"]["links"] >= 1 and "persisted" not in body


def test_no_signals_says_unknown_not_safe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, write(tmp_path, eml()))
    assert code == 0 and out.startswith("UNKNOWN  score n/a") and "not evidence of safety" in out


def test_an_unreadable_path_is_a_usage_error_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for path in (tmp_path / "missing.eml", tmp_path):
        code, out, err = run(capsys, path)
        assert code == 2 and out == "" and "cannot read" in err and "Traceback" not in err


def test_a_file_over_the_cap_is_unknown_and_not_loaded_whole(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, write(tmp_path, b"A" * (MAX_MESSAGE_BYTES + 5000)), "--json")
    assert code == 0 and json.loads(out)["reason"] == "too_large"


def test_a_sandbox_failure_exits_non_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(_raw: bytes) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("not built")

    monkeypatch.setattr(engine, "run_sandbox", unavailable)
    code, out, _ = run(capsys, write(tmp_path, eml()))
    assert code == 1 and out.startswith("ERROR") and "sandbox_unavailable" in out
