from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from eval.corpus import CorpusEntry, Label, Split, is_synthetic_host, load_manifest

MANIFEST = Path(__file__).parents[2] / "corpus" / "manifest.jsonl"
CATEGORIES = {
    "lookalike", "punycode", "shortener", "ip_based", "encoded_redirect", "credential_harvest",
}  # fmt: skip


def test_manifest_loads_with_unique_ids() -> None:
    entries = load_manifest(MANIFEST)  # also enforces unique ids and synthetic hosts
    assert len(entries) == 30


def test_covers_every_required_category_and_has_benign_hard_negatives() -> None:
    entries = load_manifest(MANIFEST)
    cats = {e.category for e in entries}
    assert cats >= CATEGORIES
    assert any(e.category.startswith("benign") for e in entries)


def test_both_labels_present_in_both_splits() -> None:
    seen = Counter((e.label, e.split) for e in load_manifest(MANIFEST))
    for label in Label:
        for split in Split:
            assert seen[(label, split)] > 0, (label, split)


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("login.examplebank.test", True),
        ("xn--exmplebank-hmf.test", True),
        ("x.invalid", True),
        ("www.example.com", True),
        ("203.0.113.45", True),
        ("2001:db8::7", True),
        ("8.8.8.8", False),
        ("example.com.evil.com", False),
        ("notexample.com", False),
        ("", False),
        (None, False),
    ],
)
def test_synthetic_host_check(host: str | None, ok: bool) -> None:
    assert is_synthetic_host(host) is ok


def test_real_host_is_rejected_at_load() -> None:
    with pytest.raises(ValidationError):
        CorpusEntry(
            id="x", value="https://realsite.com/", label=Label.BENIGN, category="c",
            source="s", split=Split.DEV,
        )  # fmt: skip
