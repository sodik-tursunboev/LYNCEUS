"""The message corpus: well-formed, safe to hold, pinned, and dev results that do not regress.

Synthetic positives measure rule correctness, not real-world detection (same author wrote the
messages and the rules). A change to these floors needs a written reason.
"""

from collections import Counter
from pathlib import Path

import pytest
from mailhelp import analyze, parsed

from core.contracts import VerdictState
from eval.corpus import Label, Origin, Split, split_hash
from eval.mailcorpus import (
    MAX_FILE_BYTES,
    MailEntry,
    foreign_hosts,
    load_mail_manifest,
    read_message,
)

MAIL = Path(__file__).parents[2] / "corpus" / "mail"
MANIFEST = MAIL / "manifest.jsonl"
FLAGGED = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)


@pytest.fixture(scope="module")
def entries() -> list[MailEntry]:
    return load_mail_manifest(
        MANIFEST
    )  # checks hashes, size and that every destination is synthetic


def test_size_and_splits(entries: list[MailEntry]) -> None:
    sizes = Counter(e.split for e in entries)
    assert len(entries) >= 100
    assert sizes[Split.DEV] >= 70 and sizes[Split.HOLDOUT] >= 20 and sizes[Split.RESERVE] >= 15


def test_both_labels_in_every_split(entries: list[MailEntry]) -> None:
    assert {(e.label, e.split) for e in entries} == {(lbl, s) for lbl in Label for s in Split}


def test_every_file_in_the_folder_is_in_the_manifest(entries: list[MailEntry]) -> None:
    assert {p.name for p in MAIL.glob("*.eml")} == {e.file for e in entries}


def test_real_hosts_are_benign_only_and_documented(entries: list[MailEntry]) -> None:
    real = [e for e in entries if e.origin is Origin.PUBLIC_REAL]
    assert all(e.label is Label.BENIGN and e.source.startswith("public:") for e in real)
    assert all(e.origin is Origin.SYNTHETIC for e in entries if e.label is Label.MALICIOUS)


def test_holdout_and_reserve_are_pinned() -> None:
    pins = dict(
        line.split() for line in (MAIL / "pins.txt").read_text().splitlines() if line.strip()
    )
    for split in (Split.HOLDOUT, Split.RESERVE):
        assert split_hash(MANIFEST, split) == pins[split.value], (
            f"{split.value} changed. If that is deliberate, say why in the commit and run "
            "python -m eval.corpus corpus/mail/manifest.jsonl"
        )


def test_no_message_is_big_or_points_at_a_real_destination(entries: list[MailEntry]) -> None:
    for e in entries:
        raw = read_message(MANIFEST, e)
        assert len(raw) <= MAX_FILE_BYTES
        if e.origin is Origin.SYNTHETIC:
            assert foreign_hosts(raw) == [], e.id


def test_the_validator_rejects_a_real_destination() -> None:
    real = (
        b'From: a@x.test\r\nContent-Type: text/html\r\n\r\n<a href="https://realsite.com/x">go</a>'
    )
    assert foreign_hosts(real) == ["realsite.com"]
    shown = b'From: a@x.test\r\nContent-Type: text/html\r\n\r\n<a href="https://evil.test/">https://www.paypal.com/x</a>'
    assert foreign_hosts(shown) == []  # a real brand name may be *shown*, never a destination


# ---- what the engine does with them --------------------------------------------------------------


def test_the_parser_output_is_valid_for_every_message(entries: list[MailEntry]) -> None:
    for e in entries:
        assert parsed(read_message(MANIFEST, e)).sha256, e.id


def test_no_message_is_ever_benign(entries: list[MailEntry]) -> None:
    states = {analyze(read_message(MANIFEST, e)).report.verdict.state for e in entries}
    assert states <= {VerdictState.UNKNOWN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS}


def test_dev_split_floor(entries: list[MailEntry]) -> None:
    dev = [e for e in entries if e.split is Split.DEV]
    verdicts = {e.id: analyze(read_message(MANIFEST, e)).report.verdict.state for e in dev}
    missed = [e.id for e in dev if e.label is Label.MALICIOUS and verdicts[e.id] not in FLAGGED]
    false_alarms = [e.id for e in dev if e.label is Label.BENIGN and verdicts[e.id] in FLAGGED]
    assert missed == [] and false_alarms == []


def test_every_malicious_category_is_flagged_on_dev(entries: list[MailEntry]) -> None:
    flagged: dict[str, int] = Counter()
    seen: dict[str, int] = Counter()
    for e in entries:
        if e.split is Split.DEV and e.label is Label.MALICIOUS:
            seen[e.category] += 1
            if analyze(read_message(MANIFEST, e)).report.verdict.state in FLAGGED:
                flagged[e.category] += 1
    assert seen and flagged == seen
