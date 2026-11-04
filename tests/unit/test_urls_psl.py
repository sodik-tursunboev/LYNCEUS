import hashlib
import re

import pytest

from core.urls import psl

PROVENANCE = psl.DATA.parent / "PROVENANCE.md"


def test_snapshot_matches_its_recorded_provenance() -> None:
    data = psl.DATA.read_bytes()
    text = PROVENANCE.read_text(encoding="utf-8")
    recorded = re.search(r"SHA-256 \| `([0-9a-f]{64})`", text)
    assert recorded, "PROVENANCE.md must record the SHA-256"
    assert hashlib.sha256(data).hexdigest() == recorded.group(1), (
        "the PSL file changed: update PROVENANCE.md on purpose (source, date, version, hash)"
    )
    assert f"{len(data)} bytes" in text
    assert "Mozilla Public License" in text and b"Mozilla Public" in data[:200]
    assert re.search(rb"// VERSION: \d{4}-\d{2}-\d{2}", data)


def test_both_sections_are_loaded() -> None:
    rules = psl._load()
    assert len(rules.plain) > 8000
    assert rules.plain["com"] is False and rules.plain["github.io"] is True


@pytest.mark.parametrize(
    ("host", "suffix", "registered", "private"),
    [
        ("bbc.co.uk", "co.uk", "bbc.co.uk", False),
        ("a.b.c.example.co.uk", "co.uk", "example.co.uk", False),
        ("a.b.c.example.com", "com", "example.com", False),
        ("co.uk", "co.uk", None, False),
        ("com", "com", None, False),
        ("localhost", "localhost", None, False),
        ("evil.test", "test", "evil.test", False),  # unknown TLD: the implicit "*" rule
        ("foo.github.io", "github.io", "foo.github.io", True),
        ("github.io", "github.io", None, True),
        ("a.foo.github.io", "github.io", "foo.github.io", True),
        # Wildcard (*.ck) and exception (!www.ck) rules.
        ("x.ck", "x.ck", None, False),
        ("a.x.ck", "x.ck", "a.x.ck", False),
        ("www.ck", "ck", "www.ck", False),
        ("sub.www.ck", "ck", "www.ck", False),
        # IDN suffix, as punycode.
        ("example.xn--p1ai", "xn--p1ai", "example.xn--p1ai", False),
    ],
)
def test_lookup(host: str, suffix: str, registered: str | None, private: bool) -> None:
    assert psl.lookup(host) == (suffix, registered, private)


def test_every_plain_rule_resolves_to_itself() -> None:
    rules = psl._load()
    for rule in rules.plain:
        if rule in rules.exception or "." not in rule and rule in rules.wildcard:
            continue
        assert psl.lookup(rule).public_suffix == rule, rule
