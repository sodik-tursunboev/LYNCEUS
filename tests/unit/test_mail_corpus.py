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


# Tests judge the DEV split only: the holdout and reserve are run by the eval CLI, once, and logged.
# Dev messages the engine is known not to flag. Each is a deliberate abstention (a weak signal on
# its own, ADR-014), kept in the corpus so the miss is counted; a change here needs a reason.
KNOWN_MISSES = {
    "m2b-018": "a PDF with an embedded file and nothing else (pdf_embedded_file is 0.4 alone)",
    # m2b-025 (a QR code to a login-looking domain with no brand) is caught since AI1: the learned
    # domain model rates that domain as phishing-like
}


@pytest.fixture(scope="module")
def dev_verdicts(entries: list[MailEntry]) -> dict[str, VerdictState]:
    dev = [e for e in entries if e.split is Split.DEV]
    return {e.id: analyze(read_message(MANIFEST, e)).report.verdict.state for e in dev}


def test_no_dev_message_is_ever_benign(dev_verdicts: dict[str, VerdictState]) -> None:
    states = set(dev_verdicts.values())
    assert states <= {VerdictState.UNKNOWN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS}


def test_dev_split_floor(entries: list[MailEntry], dev_verdicts: dict[str, VerdictState]) -> None:
    verdicts = dev_verdicts
    labels = {e.id: e.label for e in entries}
    missed = {i for i, v in verdicts.items() if labels[i] is Label.MALICIOUS and v not in FLAGGED}
    false_alarms = [i for i, v in verdicts.items() if labels[i] is Label.BENIGN and v in FLAGGED]
    assert missed == set(KNOWN_MISSES) and false_alarms == []


def test_every_malicious_category_is_mostly_flagged_on_dev(
    entries: list[MailEntry], dev_verdicts: dict[str, VerdictState]
) -> None:
    verdicts = dev_verdicts
    flagged: dict[str, int] = Counter()
    seen: dict[str, int] = Counter()
    for e in entries:
        if e.split is Split.DEV and e.label is Label.MALICIOUS:
            seen[e.category] += 1
            flagged[e.category] += verdicts[e.id] in FLAGGED
    assert seen and all(flagged[c] / n >= 0.5 for c, n in seen.items() if n >= 2), (flagged, seen)
