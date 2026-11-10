"""The real-data URL evaluation (E1): its splits, its plain-number scorer and its report. No real
dataset is read here: the samples are made up (.test hosts) and the files are built in tmp_path."""

import bz2
import io
import json
import random
import zipfile
from pathlib import Path

import pytest

from core.detection.engine import analyze_url
from eval import realurl as r
from rules.url import RULES
from rules.url.data import scoring


def test_the_split_is_fixed_by_the_url_alone_and_roughly_60_30_10() -> None:
    urls = [f"https://host{i}.test/p{i}" for i in range(20_000)]
    first = [r.split_of(u) for u in urls]
    assert first == [r.split_of(u) for u in urls]
    shares = {k: first.count(k) / len(first) for k in ("train", "test", "reserve")}
    assert abs(shares["train"] - 0.6) < 0.02 and abs(shares["test"] - 0.3) < 0.02
    assert abs(shares["reserve"] - 0.1) < 0.02


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("http://192.0.2.7/login", "ip_address"),
        ("https://xn--pypal-4ve.test/", "punycode"),
        ("https://bit.ly/abc", "shortener"),
        ("https://evil-kit.pages.dev/sign-in", "platform"),
        ("https://docs.google.com/forms/d/x", "platform"),
        ("https://shop.example-store.test/cart", "own_domain"),
        ("not a url", "unparsable"),
    ],
)
def test_hosts_are_sorted_into_kinds(url: str, kind: str) -> None:
    assert r.host_kind(url) == kind


@pytest.mark.parametrize(
    ("url", "path"),
    [("https://a.test", False), ("https://a.test/", False), ("https://a.test/x", True),
     ("https://a.test/?q=1", True)],
)  # fmt: skip
def test_home_pages_and_urls_with_a_path_are_told_apart(url: str, path: bool) -> None:
    assert r.has_path(url) is path


def test_the_plain_number_scorer_agrees_with_the_engine_on_random_rule_combinations() -> None:
    from core.contracts import Signal
    from core.risk.scoring import score

    cfg = scoring()
    cats = {rule.id: rule.category for rule in RULES}
    ids = sorted(cfg["weights"])
    rng = random.Random(5)
    for _ in range(3000):
        chosen = tuple(sorted(rng.sample(ids, rng.randint(0, 5))))
        allow = rng.random() < 0.1
        signals = [
            Signal(rule_id=i, category=cats[i], weight=cfg["weights"][i], description="d")
            for i in chosen
        ]
        assert (
            r.fast_state(chosen, allow, cfg["weights"], cats, cfg)
            == score(signals, allow, cfg).state.value
        )


def test_the_judge_uses_the_real_engine_and_never_raises() -> None:
    urls = [
        "https://paypal.com.secure-login.account-verify.test/signin",
        "https://shop.test/",
        "::::",
        "http://" + "a" * 9000,
    ]
    judged = r.judge([r.Sample("t", r.PHISH, u) for u in urls], 1)
    assert [j[0] for j in judged][:2] == [
        analyze_url(urls[0]).verdict.state.value,
        analyze_url(urls[1]).verdict.state.value,
    ]
    assert len(judged) == 4


def _datasets(tmp_path: Path) -> Path:
    d = tmp_path / "eval"
    d.mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        rows = ["FILENAME,URL,label"] + [f"f{i},https://legit{i}.test/,1" for i in range(40)]
        rows += [
            f"p{i},https://paypal.com.login-{i}.verify.test/signin?email=a%40b.test,0"
            for i in range(40)
        ]
        z.writestr("PhiUSIIL_Phishing_URL_Dataset.csv", "\n".join(rows))
    (d / "phiusiil.zip").write_bytes(buf.getvalue())
    feed = [{"url": f"http://203.0.113.{i}/secure/login", "verified": "yes"} for i in range(30)]
    feed.append({"url": "http://unverified.test/", "verified": "no"})
    (d / "phishtank.json.bz2").write_bytes(bz2.compress(json.dumps(feed).encode()))
    (d / "openphish.txt").write_text("https://kit.pages.dev/office\nnot a url\n", encoding="utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "\r\n".join(f"{i},popular{i}.test" for i in range(1, 30)))
    (d / "tranco-top-1m.csv.zip").write_bytes(buf.getvalue())
    return d


def test_the_whole_run_reports_counts_and_never_a_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        r,
        "edge_history",
        lambda: iter([r.Sample("edge_history", r.LEGIT, "https://private-page.test/doc/42")]),
    )
    out = tmp_path / "out"
    assert (
        r.main(
            [
                "--data",
                str(_datasets(tmp_path)),
                "--out",
                str(out),
                "--tranco",
                "20",
                "--workers",
                "1",
            ]
        )
        == 0
    )
    report = json.loads((out / "url-real.json").read_text(encoding="utf-8"))
    text = (out / "url-real.json").read_text(encoding="utf-8") + (out / "url-real.md").read_text(
        encoding="utf-8"
    )
    for leaked in (".test/", "203.0.113", "pages.dev/office", "private-page", "paypal.com.login"):
        assert leaked not in text, leaked
    assert report["scorer_mismatches"] == 0
    sources = report["measure"]["sources"]
    assert set(sources) == {
        "phiusiil legit",
        "phiusiil phish",
        "phishtank phish",
        "openphish phish",
        "tranco legit",
        "edge_history legit",
    }  # fmt: skip  (one row per source AND label: PhiUSIIL holds both)
    assert sources["phishtank phish"]["n"] <= 30  # the unverified entry is left out
    assert sources["phiusiil legit"]["label"] == "legit"
    assert sources["phiusiil phish"]["label"] == "phish"
    caught = report["measure"]["phishing"]["all"]
    assert caught["n"] > 0 and caught["ci"][0] <= caught["rate"] <= caught["ci"][1]
    assert report["fit"] is not None and "adopt" in report["fit"]


def test_the_evaluation_opens_no_network_connection() -> None:
    source = Path(r.__file__).read_text(encoding="utf-8")
    for module in ("socket", "httpx", "requests", "urllib.request", "http.client", "core.intel"):
        assert f"import {module}" not in source and f"from {module}" not in source
