"""The file-type table is shared with the Windows agent (FileSignatures.cs): both are tested
against tests/fixtures/filetypes.json, so they cannot drift apart unnoticed."""

import json
from pathlib import Path
from typing import Any

import pytest
from filetype import detect_magic

FIXTURE = Path(__file__).parents[1] / "fixtures" / "filetypes.json"
CASES: list[dict[str, Any]] = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


def build(case: dict[str, Any]) -> bytes:
    body = bytes.fromhex(case["hex"]) if "hex" in case else case["text"].encode("utf-8")
    return b"\x00" * case.get("at", 0) + body


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_detector_agrees_with_the_shared_fixture(case: dict[str, Any]) -> None:
    assert detect_magic(build(case)) == case["expect"]


def test_the_fixture_covers_every_type_the_core_accepts() -> None:
    from core.email.models import Magic

    wanted = set(Magic.__args__)  # type: ignore[attr-defined]
    assert wanted - {c["expect"] for c in CASES} == set()
