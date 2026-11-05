import hashlib
import json
from pathlib import Path

import pytest
from mailhelp import eml, in_process

from core.contracts import VerdictState as V
from core.detection import stub
from core.email import engine as email_engine
from eval.__main__ import EvalReport, Result, main, rule_stats, run
from eval.corpus import Label, load_manifest
from eval.mailcorpus import load_mail_manifest
from eval.metrics import percentile, rates, tally, wilson

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
    report = EvalReport.model_validate_json((tmp_path / "dev.json").read_text(encoding="utf-8"))
    assert report.split == "dev"  # the default; holdout is explicit, reserve is not selectable
    assert report.counts.n == sum(e.split.value == "dev" for e in load_manifest(MANIFEST))
    assert "+" in report.ruleset_version and report.rules
    assert not (tmp_path / "holdout_runs.md").exists()
    with pytest.raises(SystemExit):
        main(["--manifest", str(MANIFEST), "--out", str(tmp_path), "--split", "reserve"])
    md = (tmp_path / "dev.md").read_text(encoding="utf-8")
    assert md.startswith("# Eval report") and "Wilson" in md
    assert "not the real-world detection rate" in md
    assert "Precision" in capsys.readouterr().out


MAIL_MANIFEST = Path(__file__).parents[2] / "corpus" / "mail" / "manifest.jsonl"


def test_mail_eval_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(email_engine, "run_sandbox", in_process)
    assert main(["--kind", "mail", "--manifest", str(MAIL_MANIFEST), "--out", str(tmp_path)]) == 0
    report = EvalReport.model_validate_json(
        (tmp_path / "mail-dev.json").read_text(encoding="utf-8")
    )
    assert (report.kind, report.split) == ("mail", "dev")
    assert report.engine_version.startswith("email-") and "+" in report.ruleset_version
    dev = [e for e in load_mail_manifest(MAIL_MANIFEST) if e.split.value == "dev"]
    assert report.counts.n == len(dev)
    assert (tmp_path / "mail-dev.md").read_text(encoding="utf-8").startswith("# Eval report (mail)")
    assert not (tmp_path / "dev.json").exists()  # the URL report is a separate file


def test_mail_holdout_runs_are_logged_in_their_own_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(email_engine, "run_sandbox", in_process)
    raw = eml()
    (tmp_path / "h1.eml").write_bytes(raw)
    line = {
        "id": "h1", "file": "h1.eml", "file_sha256": hashlib.sha256(raw).hexdigest(),
        "label": "benign", "category": "c", "origin": "synthetic", "source": "s", "notes": "",
        "split": "holdout",
    }  # fmt: skip
    manifest = tmp_path / "m.jsonl"
    manifest.write_text(json.dumps(line) + "\n", encoding="utf-8")
    args = [
        "--kind",
        "mail",
        "--manifest",
        str(manifest),
        "--out",
        str(tmp_path),
        "--split",
        "holdout",
    ]
    assert main(args) == 0 and main(args) == 0
    rows = (tmp_path / "mail_holdout_runs.md").read_text(encoding="utf-8").splitlines()
    assert sum(r.startswith("| 20") for r in rows) == 2
    assert not (tmp_path / "holdout_runs.md").exists()


def test_wilson_interval() -> None:
    assert wilson(1, 0) is None
    mid = wilson(5, 10)
    assert mid and (mid.low, mid.high) == (pytest.approx(0.2366, 1e-3), pytest.approx(0.7634, 1e-3))
    none, all_ = wilson(0, 10), wilson(10, 10)
    assert none and none.low == 0.0 and none.high == pytest.approx(0.2775, 1e-3)
    assert all_ and all_.high == 1.0 and all_.low == pytest.approx(0.7225, 1e-3)


def test_flag_rate_treats_unknown_as_not_flagged() -> None:
    r = rates(tally([(NEG, V.SUSPICIOUS), (NEG, V.UNKNOWN), (NEG, V.BENIGN), (NEG, V.ERROR)]))
    assert r.flag_rate == 0.25


def test_rule_stats() -> None:
    def result(label: Label, rules: list[str]) -> Result:
        return Result(id="x", category="c", label=label, state=V.UNKNOWN, rules=rules, latency_ms=0)

    stats = rule_stats([result(POS, ["a", "b"]), result(POS, ["a"]), result(NEG, ["a"])])
    a, b = stats
    assert (a.rule_id, a.hits, a.on_malicious, a.on_benign) == ("a", 3, 2, 1)
    assert a.precision == pytest.approx(2 / 3) and b.precision == 1.0


def test_holdout_runs_are_logged_every_time(tmp_path: Path) -> None:
    # A throwaway manifest: tests never evaluate the real holdout.
    manifest = tmp_path / "m.jsonl"
    line = {
        "id": "h1", "kind": "url", "value": "https://paypal-login.test/", "label": "malicious",
        "category": "c", "origin": "synthetic", "source": "s", "notes": "", "split": "holdout",
    }  # fmt: skip
    manifest.write_text(json.dumps(line) + "\n", encoding="utf-8")
    args = ["--manifest", str(manifest), "--out", str(tmp_path), "--split", "holdout"]
    assert main(args) == 0 and main(args) == 0
    rows = (tmp_path / "holdout_runs.md").read_text(encoding="utf-8").splitlines()
    assert sum(r.startswith("| 20") for r in rows) == 2
