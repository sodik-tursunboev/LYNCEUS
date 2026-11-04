from pathlib import Path

import pytest

from core.contracts import VerdictState as V
from core.detection import stub
from eval.__main__ import EvalReport, main, run
from eval.corpus import Label, load_manifest
from eval.metrics import percentile, rates, tally

MANIFEST = Path(__file__).parents[2] / "corpus" / "manifest.jsonl"
POS, NEG = Label.MALICIOUS, Label.BENIGN


def test_abstaining_on_everything_scores_zero_recall_not_perfect() -> None:
    c = tally([(POS, V.UNKNOWN)] * 5 + [(NEG, V.UNKNOWN)] * 5)
    r = rates(c)
    assert (c.tp, c.fp, c.tn, c.fn) == (0, 0, 0, 5)
    assert r.recall == 0.0 and r.f1 == 0.0
    assert r.precision is None  # undefined, not 1.0
    assert r.abstain_rate == 1.0 and r.error_rate == 0.0


def test_abstention_cannot_inflate_recall() -> None:
    r = rates(tally([(POS, V.MALICIOUS)] + [(POS, V.UNKNOWN)] * 9))
    assert r.recall == pytest.approx(0.1)  # headline: abstentions are misses
    assert r.recall_answered == 1.0  # shown next to it, never instead of it
    assert r.precision == 1.0


def test_unknown_and_error_are_never_benign() -> None:
    c = tally([(NEG, V.UNKNOWN), (NEG, V.ERROR), (POS, V.UNKNOWN), (POS, V.ERROR)])
    assert c.tn == 0 and c.fn_benign == 0 and c.fp == 0
    assert (c.abstain_neg, c.error_neg, c.abstain_pos, c.error_pos) == (1, 1, 1, 1)


def test_confusion_counts() -> None:
    pairs = [
        (POS, V.MALICIOUS), (POS, V.SUSPICIOUS), (POS, V.BENIGN),
        (NEG, V.SUSPICIOUS), (NEG, V.BENIGN), (NEG, V.BENIGN),
    ]  # fmt: skip
    c = tally(pairs)
    r = rates(c)
    assert (c.tp, c.fp, c.fn, c.tn) == (2, 1, 1, 2)
    assert r.precision == pytest.approx(2 / 3)
    assert r.recall == pytest.approx(2 / 3)
    assert r.f1 == pytest.approx(2 / 3)


def test_percentile_nearest_rank() -> None:
    assert percentile([], 95) == 0.0
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50) == 5
    assert percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95) == 10


def test_stub_engine_never_says_benign_on_the_corpus() -> None:
    report = run(load_manifest(MANIFEST), stub.analyze)
    assert {r.state for r in report.results} == {V.UNKNOWN}


def test_splits_partition_the_corpus() -> None:
    entries = load_manifest(MANIFEST)
    parts = [run(entries, stub.analyze, s).counts.n for s in ("dev", "holdout", "reserve")]
    assert sum(parts) == len(entries) == run(entries, stub.analyze).counts.n
    assert all(parts)


def test_cli_end_to_end_writes_schema_valid_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--manifest", str(MANIFEST), "--out", str(tmp_path)]) == 0
    report = EvalReport.model_validate_json((tmp_path / "latest.json").read_text(encoding="utf-8"))
    assert report.split == "dev"  # the default; holdout is explicit, reserve is not selectable
    assert report.counts.n == sum(e.split.value == "dev" for e in load_manifest(MANIFEST))
    with pytest.raises(SystemExit):
        main(["--manifest", str(MANIFEST), "--out", str(tmp_path), "--split", "reserve"])
    assert report.rates.abstain_rate == 1.0
    assert (tmp_path / "latest.md").read_text(encoding="utf-8").startswith("# Eval report")
    assert "precision" in capsys.readouterr().out
