import json

import pytest

from core.cli import main
from core.contracts import Verdict
from core.detection import engine


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str]:
    code = main(["analyze-url", *args])
    return code, capsys.readouterr().out


def test_text_output_names_the_verdict_and_the_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "https://paypal.com@secure-check.test/login.php")
    assert code == 0
    assert out.split()[0] in ("SUSPICIOUS", "MALICIOUS")
    assert "url.userinfo_deception" in out and "T1566.002" in out and "applied none" in out


def test_json_output_is_the_report(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "https://paypal-login.test/", "--json")
    body = json.loads(out)
    assert code == 0 and body["normalized_url"] == "https://paypal-login.test/"
    Verdict.model_validate(body["verdict"])


def test_no_signals_says_unknown_not_safe(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "https://example.test/")
    assert code == 0 and out.startswith("UNKNOWN  score n/a")
    assert "not evidence of safety" in out


def test_unparseable_input_is_a_verdict(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "http://ex ample.test/", "--json")
    body = json.loads(out)
    assert code == 0 and body["reason"] == "unparseable"
    assert body["verdict"]["state"] == "UNKNOWN"


def test_an_internal_failure_exits_non_zero(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "_rules", boom)
    code, out = run(capsys, "https://example.test/")
    assert code == 1 and out.startswith("ERROR")


def test_usage_errors_exit_with_usage(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2
    capsys.readouterr()


def test_no_network_or_database_is_needed(capsys: pytest.CaptureFixture[str]) -> None:
    # The session guard in tests/conftest.py would fail any connection; this must simply work.
    assert run(capsys, "https://example.test/")[0] == 0
