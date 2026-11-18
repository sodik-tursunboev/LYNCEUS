"""docs/KEYS.md is the owner's step list for real keys: every secret it stores and every setting it
names must exist, and it must never hold a key-shaped value (W1). The same checks run on a faulty
sample to prove they can fail."""

import re
from pathlib import Path

from core.config import SECRET_FIELDS, Settings

GUIDE = (Path(__file__).parents[2] / "docs" / "KEYS.md").read_text(encoding="utf-8")


def stored_names(text: str) -> list[str]:
    return re.findall(r"core\.secrets (?:set|remove) ([A-Za-z0-9_]+)", text)


def unknown_secrets(text: str) -> list[str]:
    return [n for n in stored_names(text) if n not in SECRET_FIELDS]


def unknown_settings(text: str) -> list[str]:
    named = set(re.findall(r"\bLYNCEUS_([A-Z0-9_]+)\b", text))
    return sorted(n for n in named if n.lower() not in Settings.model_fields)


def key_shaped(text: str) -> list[str]:
    """A long run of letters, digits, dashes and underscores that contains a digit."""
    return re.findall(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}", text)


def test_every_secret_the_guide_stores_is_a_real_secret_setting() -> None:
    assert {"virustotal_api_key", "urlhaus_auth_key", "gmail_client_secret"} <= set(
        stored_names(GUIDE)
    )
    assert unknown_secrets(GUIDE) == []


def test_every_setting_the_guide_names_exists() -> None:
    assert {"INTEL_PROVIDERS", "GMAIL_CLIENT_ID", "GMAIL_ENABLED"} <= set(
        re.findall(r"\bLYNCEUS_([A-Z0-9_]+)\b", GUIDE)
    )
    assert unknown_settings(GUIDE) == []


def test_the_guide_holds_no_key_shaped_value() -> None:
    assert key_shaped(GUIDE) == []


def test_the_check_catches_a_misspelled_name() -> None:
    fake_key = (
        "k" + "1a2b3c4d" * 5
    )  # key-shaped (long, has digits), built here so no scanner sees a key
    bad = (
        "python -m core.secrets set virustotal_api_kee\n"
        "LYNCEUS_GMAIL_CLIENT_IDD=x\n"
        f"key {fake_key}\n"
    )
    assert unknown_secrets(bad) == ["virustotal_api_kee"]
    assert unknown_settings(bad) == ["GMAIL_CLIENT_IDD"]
    assert key_shaped(bad) == [fake_key]
