"""The macro corpus as a measurement, not a demo (ADR-023): how many unknown malicious macros are
found, and how many ordinary ones are wrongly flagged. The bars are recorded here, were set from
the first measurement, and may only change with a written reason in docs/DECISIONS.md.

The corpus is small and synthetic (tests/macrosamples.py): it measures that the analysis works as
designed, NOT how it performs on real malware. docs/KNOWN_LIMITATIONS.md says so."""

import macrosamples as ms
import olescan
from macrosamples import judge

NEW = "content.macro_", "content.vba_", "content.xlm_"
MIN_FLAGGED = 1.0  # unknown malicious macros that reach SUSPICIOUS or MALICIOUS
MIN_MALICIOUS = 0.75  # ... that reach MALICIOUS (two independent kinds of evidence)
MAX_BENIGN_MALICIOUS = 0  # ordinary macros called MALICIOUS
MAX_BENIGN_NEW_RULES = 0  # ordinary macros that fire any of the macro-analysis rules
MIN_LIFT = 3  # files the new analysis moves up to MALICIOUS that were not before it


def measure() -> dict[str, int]:
    out = {"mal": len(ms.MALICIOUS_UNKNOWN), "flagged": 0, "malicious": 0, "benign": len(ms.BENIGN),
           "benign_malicious": 0, "benign_new_rules": 0}  # fmt: skip
    for src in ms.MALICIOUS_UNKNOWN.values():
        state, _, _ = judge(src)
        out["flagged"] += state in ("SUSPICIOUS", "MALICIOUS")
        out["malicious"] += state == "MALICIOUS"
    for src in ms.BENIGN.values():
        state, _, rules = judge(src)
        out["benign_malicious"] += state == "MALICIOUS"
        out["benign_new_rules"] += any(r.startswith(NEW) for r in rules)
    return out


def test_recall_and_false_positives_meet_the_recorded_bars() -> None:
    m = measure()
    print(f"MACRO CORPUS: {m}")
    assert m["flagged"] / m["mal"] >= MIN_FLAGGED
    assert m["malicious"] / m["mal"] >= MIN_MALICIOUS
    assert m["benign_malicious"] <= MAX_BENIGN_MALICIOUS
    assert m["benign_new_rules"] <= MAX_BENIGN_NEW_RULES


def test_the_new_analysis_moves_files_the_old_one_could_not() -> None:
    with_it = measure()["malicious"]
    original = olescan.vbaanalyze.analyze
    olescan.vbaanalyze.analyze = lambda *_a, **_k: None  # type: ignore[assignment]
    try:
        without_it = measure()["malicious"]
    finally:
        olescan.vbaanalyze.analyze = original
    assert with_it - without_it >= MIN_LIFT, (with_it, without_it)


def test_the_corpus_is_what_the_bars_assume() -> None:
    assert len(ms.MALICIOUS_UNKNOWN) >= 8 and len(ms.BENIGN) >= 10
    assert set(ms.MALICIOUS_UNKNOWN) >= ms.HIDDEN_FROM_KEYWORDS
