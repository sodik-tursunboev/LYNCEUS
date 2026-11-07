"""The product was renamed MIRAGE -> Lynceus (ADR-021): the old setting names, and the old sandbox
profile, must keep working or be cleaned up exactly as documented."""

import sys
from pathlib import Path

import pytest

from core.config import Settings, legacy_env_names


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LYNCEUS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("MIRAGE_LOG_LEVEL", raising=False)


def test_an_old_name_is_still_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")
    assert Settings(_env_file=None).log_level == "DEBUG"  # type: ignore[call-arg]


def test_the_new_name_wins_over_the_old_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LYNCEUS_LOG_LEVEL", "ERROR")
    assert Settings(_env_file=None).log_level == "ERROR"  # type: ignore[call-arg]


def test_an_old_name_in_the_env_file_is_still_read(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("MIRAGE_LOG_LEVEL=WARNING\n", encoding="utf-8")
    assert Settings(_env_file=env).log_level == "WARNING"  # type: ignore[call-arg]


def test_the_new_name_in_the_env_file_wins_over_the_old_one(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("MIRAGE_LOG_LEVEL=WARNING\nLYNCEUS_LOG_LEVEL=ERROR\n", encoding="utf-8")
    assert Settings(_env_file=env).log_level == "ERROR"  # type: ignore[call-arg]


def test_old_names_in_use_are_listed_by_name_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    env.write_text("# a comment\nMIRAGE_DATA_DIR=secret-value-1\nLYNCEUS_X=1\n", encoding="utf-8")
    monkeypatch.setenv("MIRAGE_LOG_LEVEL", "secret-value-2")
    names = legacy_env_names(env)
    assert "MIRAGE_DATA_DIR" in names and "MIRAGE_LOG_LEVEL" in names
    assert all("secret" not in n and not n.startswith("LYNCEUS_") for n in names)


def test_no_old_names_is_an_empty_list(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("LYNCEUS_LOG_LEVEL=INFO\n", encoding="utf-8")
    assert not [n for n in legacy_env_names(env) if n.startswith("MIRAGE_LOG")]
    assert legacy_env_names(tmp_path / "missing.env") == legacy_env_names(None)


@pytest.mark.skipif(sys.platform != "win32", reason="the sandbox is Windows only")
def test_only_the_old_container_profile_is_removed_by_remove_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.sandbox import CONTAINER, LEGACY_CONTAINER, _win32, build

    removed: list[str] = []
    monkeypatch.setattr(_win32, "remove_container", removed.append)
    build.remove_legacy()
    assert removed == [LEGACY_CONTAINER] and CONTAINER not in removed
    assert LEGACY_CONTAINER == "mirage.parser" and CONTAINER == "lynceus.parser"
