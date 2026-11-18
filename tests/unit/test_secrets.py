"""H1 A4: secrets at rest under DPAPI. A value round-trips only for this Windows user, the store
never holds plain text, the settings read it between the environment and .env, and .env values are
reported by name only."""

import json
import os
import sys
from pathlib import Path

import pytest

from core import secrets
from core.config import SECRET_FIELDS, Settings, plaintext_secrets

pytestmark = pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows only")
TOKEN = "a-dpapi-protected-token-1234567"  # pragma: allowlist secret
DOTENV_TOKEN = "plain-text-token-in-dotenv-1234"  # pragma: allowlist secret


def test_a_value_round_trips_and_the_store_holds_no_plain_text(tmp_path: Path) -> None:
    store = tmp_path / "s.json"
    secrets.put("api_token", TOKEN, store)
    assert secrets.load(store) == {"api_token": TOKEN}
    assert TOKEN not in store.read_text(encoding="utf-8")


def test_another_programs_dpapi_blob_does_not_open_here(tmp_path: Path) -> None:
    """The entropy binds a blob to Lynceus: a blob made without it (by any other app) is refused."""
    store = tmp_path / "s.json"
    import base64

    secrets.put("api_token", TOKEN, store)
    data = json.loads(store.read_text(encoding="utf-8"))
    data["secrets"]["api_token"] = base64.b64encode(b"not a dpapi blob").decode()
    store.write_text(json.dumps(data), encoding="utf-8")
    assert secrets.load(store) == {}  # left out, never guessed


def test_remove_and_a_missing_or_broken_store(tmp_path: Path) -> None:
    store = tmp_path / "s.json"
    assert secrets.load(store) == {} and secrets.remove("api_token", store) is False
    secrets.put("api_token", TOKEN, store)
    assert secrets.remove("api_token", store) is True and secrets.load(store) == {}
    store.write_text("{not json", encoding="utf-8")
    assert secrets.load(store) == {}


def test_settings_read_the_store_after_the_environment_and_before_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "s.json"
    secrets.put("api_token", TOKEN, store)
    monkeypatch.setattr(secrets, "STORE", store)
    env = tmp_path / ".env"
    env.write_text(f"LYNCEUS_API_TOKEN={DOTENV_TOKEN}\n", encoding="utf-8")
    monkeypatch.delenv("LYNCEUS_API_TOKEN", raising=False)
    monkeypatch.delenv("MIRAGE_API_TOKEN", raising=False)
    s = Settings(_env_file=env)
    assert s.api_token is not None and s.api_token.get_secret_value() == TOKEN
    monkeypatch.setenv("LYNCEUS_API_TOKEN", "from-the-environment-123456")
    assert Settings(_env_file=env).api_token.get_secret_value() == "from-the-environment-123456"  # type: ignore[union-attr]


class _Stdin:
    def __init__(self, tty: bool, text: str = "") -> None:
        self.tty, self.text = tty, text

    def isatty(self) -> bool:
        return self.tty

    def readline(self) -> str:
        return self.text


def test_a_value_typed_at_a_terminal_is_hidden_and_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "s.json"
    monkeypatch.setattr(secrets, "STORE", store)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))
    asked: list[str] = []

    def hidden(prompt: str) -> str:
        asked.append(prompt)
        return f"  {TOKEN}  "

    monkeypatch.setattr(secrets.getpass, "getpass", hidden)
    assert secrets.main(["set", "virustotal_api_key"]) == 0
    assert asked and "virustotal_api_key" in asked[0]  # asked by name, through getpass (no echo)
    assert secrets.load(store) == {"virustotal_api_key": TOKEN}
    assert TOKEN not in capsys.readouterr().out  # never printed back


def test_a_piped_value_is_read_from_standard_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "s.json"
    monkeypatch.setattr(secrets, "STORE", store)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False, text=f"{TOKEN}\n"))
    monkeypatch.setattr(
        secrets.getpass, "getpass", lambda p: pytest.fail("a pipe is not a terminal")
    )
    assert secrets.main(["set", "urlhaus_auth_key"]) == 0
    assert secrets.load(store) == {"urlhaus_auth_key": TOKEN}
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False, text="\n"))
    assert secrets.main(["set", "urlhaus_auth_key"]) == 2  # an empty value stores nothing


def test_a_byte_order_mark_from_a_powershell_pipe_is_not_part_of_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = tmp_path / "s.json"
    monkeypatch.setattr(secrets, "STORE", store)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False, text=f"﻿{TOKEN}\r\n"))
    assert secrets.main(["set", "virustotal_api_key"]) == 0
    assert secrets.load(store) == {"virustotal_api_key": TOKEN}  # no U+FEFF in front


def test_only_secret_settings_may_be_stored() -> None:
    assert {
        "api_token",
        "database_url",
        "virustotal_api_key",
        "gmail_client_secret",
    } <= SECRET_FIELDS
    assert "log_level" not in SECRET_FIELDS and "data_dir" not in SECRET_FIELDS


def test_plain_text_secrets_in_dotenv_are_named_never_shown(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("LYNCEUS_API_TOKEN=abc\nMIRAGE_DATABASE_URL=postgresql://u:p@h/d\n"
                   "LYNCEUS_LOG_LEVEL=INFO\n# LYNCEUS_VIRUSTOTAL_API_KEY=commented\n"
                   "LYNCEUS_URLSCAN_API_KEY=\n", encoding="utf-8")  # fmt: skip
    assert plaintext_secrets(env) == ["api_token", "database_url"]
