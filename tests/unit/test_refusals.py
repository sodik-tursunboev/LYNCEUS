"""Refusal classes (DA5 0b) and the opener's filter on page-only catches (0d). Every page text here
is made up; no kept page is read."""

import json
from pathlib import Path
from typing import Any

import pytest

from core.detonate.models import PageForm, PageReport
from eval import refusals as r
from eval.detonate import SPLITS, _key
from eval.realurl import LEGIT, PHISH

LONG = "word " * 60  # 300 characters
F = r.Facts


def cls(f: r.Facts) -> str:
    return r.classify(f)[0]


# One positive and one negative control per class. A negative is a look-alike that must land in
# another class.
POSITIVE = [
    ("takedown", F("ok", 404, title="Not Found", text="nothing here")),
    ("takedown", F("ok", 403, title="Suspected phishing", text="this site was flagged", form=True)),
    ("takedown", F("ok", 200, text="This domain is for sale. Buy this domain today.")),
    ("takedown", F("ok", 403, text="refused: dns")),
    ("challenge", F("ok", 403, title="Just a moment...", text="")),
    ("challenge", F("ok", 200, text="Please complete the captcha to continue")),
    ("blocked", F("ok", 403, title="Access Denied", text="You don't have permission to access it")),
    ("blocked", F("ok", 429, text="slow down")),
    ("blocked", F("ok", 200, title="Attention Required!", text="Sorry, you have been blocked")),
    ("empty_stub", F("ok", 200, title="Home", text="Loading")),
    ("empty_stub", F("ok", 200)),
    ("other", F("ok", 500, text="boom")),
    ("other", F("ok", 200, text="Sign in", form=True)),
    ("other", F("ok", 403, text="refused: private_address")),
    ("unknown_no_body", F("dead", None, error="err_tunnel_connection_failed")),
    ("unknown_no_body", F("error", None, error="watchdog")),
]
NEGATIVE = [  # (class it must not be, the look-alike)
    ("takedown", F("ok", 403, title="Access Denied", text="You don't have permission")),
    ("takedown", F("ok", 200, text="Welcome to our shop")),
    ("challenge", F("ok", 403, title="Access Denied", text="You don't have permission")),
    ("challenge", F("ok", 200, title="Attention Required!", text="Sorry, you have been blocked")),
    ("blocked", F("ok", 404, title="Not Found", text="nothing here")),
    ("blocked", F("ok", 403, title="Just a moment...", text="")),  # a challenge answered with 403
    ("empty_stub", F("ok", 200, text="Sign in", form=True)),
    ("empty_stub", F("dead", None, error="err_tunnel_connection_failed")),
    ("empty_stub", F("ok", 404, text="gone")),
    ("other", F("ok", 404, text="gone")),
    ("other", F("ok", 200, text="Loading")),
    ("unknown_no_body", F("ok", 403)),  # a refusal with a status is a block, not a mystery
    ("unknown_no_body", F("ok", 200)),  # loaded and blank: an empty stub
    ("unknown_no_body", F("dead", None, title="Parking", text="This domain is for sale")),
]


@pytest.mark.parametrize(("expected", "facts"), POSITIVE)
def test_positive_controls(expected: str, facts: r.Facts) -> None:
    assert r.in_scope(facts)
    assert cls(facts) == expected


@pytest.mark.parametrize(("forbidden", "facts"), NEGATIVE)
def test_negative_controls(forbidden: str, facts: r.Facts) -> None:
    assert cls(facts) != forbidden


def test_every_class_has_a_positive_control() -> None:
    assert {c for c, _ in POSITIVE} == set(r.CLASSES)


def test_a_forged_proxy_line_is_not_the_proxy() -> None:
    assert r.classify(F("ok", 403, text="refused: dns")) == ("takedown", "proxy_dns")
    assert r.classify(F("ok", 403, text="refused: private_address"))[1] == "proxy_private_address"
    # only the exact line, only on a 403: the site's own text is never read as the sandbox's
    assert r.classify(F("ok", 200, text="refused: dns"))[1] != "proxy_dns"
    assert r.classify(F("ok", 403, text="refused: dns " + LONG))[1] != "proxy_dns"


def test_a_host_notice_notes_a_form_without_calling_it_a_live_page() -> None:
    assert r.classify(F("ok", 403, title="Suspected phishing", form=True)) == (
        "takedown",
        "host_notice+form",
    )
    assert r.classify(F("ok", 403, title="Suspected phishing")) == ("takedown", "host_notice")


def test_a_parking_host_is_a_takedown_whatever_the_text() -> None:
    assert r.classify(F("ok", 200, text="hello", final_host="x.sedoparking.com"))[0] == "takedown"
    assert r.classify(F("ok", 200, text="hello", final_host="notsedoparking.com"))[0] != "takedown"


def test_who_is_classified() -> None:
    assert not r.in_scope(F("ok", 200, text=LONG))  # loaded and long: nothing to explain
    assert r.in_scope(F("ok", 200, text="x" * 199))
    assert not r.in_scope(F("ok", 200, text="x" * 200))
    assert r.in_scope(F("ok", 403, text=LONG))  # refused, however long
    assert r.in_scope(F("dead", None, text=LONG))
    assert r.in_scope(F("partial", 503, text=LONG))


@pytest.mark.parametrize(
    "facts",
    [
        F(),
        F("", None, "", "", ""),
        F("ok", 200, text="a" * 5_000_000),
        F("ok", 403, title="x" * 100_000, text="\x00" * 10_000),
        F("ok", 404, text="\ud800 lone surrogate \udfff"),
        F("ok", 10**9, text="odd status"),
        F("ok", -1, text="odd status"),
        F("nonsense", 0, error="refused: ", text="refused: " + "_" * 30),
        F("ok", 403, text="refused: " + "a" * 40),
        F("dead", None, error="err_" * 1000, final_host="." * 500),
        F("ok", 200, text="captcha " * 100_000, title="just a moment" * 1000),
        F("ok", 403, text="<script>alert(1)</script> ${jndi:ldap://x} %s %n {0}", form=True),
        F(None, None, None, None, None, None, None),  # type: ignore[arg-type]
        F(status=7, http=True, error=[], title={}, text=b"bytes"),  # type: ignore[arg-type]
    ],
)
def test_the_classifier_never_raises_and_always_names_a_class(facts: r.Facts) -> None:
    got = r.classify(facts)
    assert got[0] in r.CLASSES
    assert isinstance(got[1], str)
    r.in_scope(facts)


def test_facts_survive_a_malformed_final_address() -> None:
    page = PageReport(status="ok", http_status=200, final_url="http://[::1/", text="hi")
    assert r.facts_of(page).final_host == ""
    form = PageForm(action="https://x.test/", method="post", fields=[])
    assert r.facts_of(PageReport(status="ok", forms=[form])).form is False  # no field, no form


# ---- a synthetic run -------------------------------------------------------------------------


def _pages(n: int) -> tuple[list[dict[str, Any]], dict[str, PageReport]]:
    shapes = [
        PageReport(status="ok", http_status=404, text="gone"),
        PageReport(status="ok", http_status=403, title="Just a moment...", text="wait"),
        PageReport(status="ok", http_status=403, text="Access denied"),
        PageReport(status="ok", http_status=200, text="hi"),
        PageReport(status="ok", http_status=500, text="boom"),
        PageReport(status="dead", error="err_tunnel_connection_failed"),
        PageReport(status="ok", http_status=200, text=LONG),  # not classified
    ]
    rows, pages = [], {}
    for i in range(n):
        url = f"https://host{i}.test/p"
        rows.append({"url": url, "label": PHISH if i % 2 else LEGIT, "split": SPLITS[(i // 2) % 2]})
        pages[url] = shapes[i % len(shapes)]
    return rows, pages


def _report(n: int = 400) -> dict[str, Any]:
    rows, pages = _pages(n)
    judged = [
        {
            **row,
            "alive": pages[row["url"]].alive,
            "state": "SUSPICIOUS",
            "url_state": "UNKNOWN" if i % 3 else "BENIGN",
            "auto_open": bool(i % 4),
        }
        for i, row in enumerate(rows)
    ]
    run = {**r.summarize(rows, pages), "page_only": r.page_only(judged, True)}
    return {"generated": "2026-01-01T00:00:00+00:00", "runs": {"synthetic": run}}


def test_the_classes_sum_to_the_classified_total_in_every_group() -> None:
    run = _report()["runs"]["synthetic"]
    assert run["classified"] > 150
    for half in r.HALVES:
        for label in (PHISH, LEGIT):
            g = run["groups"][half][label]
            assert sum(g["classes"][c]["k"] for c in r.CLASSES) == g["classified"]
            assert sum(g["details"].values()) == g["classified"]
            assert sum(g["http_403"].values()) <= g["classified"]
    both = sum(run["groups"]["all"][lab]["classified"] for lab in (PHISH, LEGIT))
    halves = sum(run["groups"][h][lab]["classified"] for h in SPLITS for lab in (PHISH, LEGIT))
    assert both == halves == run["classified"]
    assert r.verify(_report()) == []


def test_the_long_page_is_left_out_and_the_refused_ones_are_in() -> None:
    rows, pages = _pages(14)
    run = r.summarize(rows, pages)
    assert run["classified"] == 12  # 14 pages, two of them the long 200 OK
    assert run["rows_without_page"] == 0
    assert run["phone_view"] is None  # no visit time on any page: the phone retry cannot be told


def test_a_row_without_a_kept_page_is_counted_not_classified() -> None:
    rows, pages = _pages(4)
    del pages[rows[0]["url"]]
    run = r.summarize(rows, pages)
    assert run["rows_without_page"] == 1 and run["kept_pages"] == 3


def test_load_reads_rows_and_pages_by_the_detonators_key(tmp_path: Path) -> None:
    rows, pages = _pages(3)
    (tmp_path / "pages").mkdir()
    (tmp_path / "results.jsonl").write_text("\n".join(map(json.dumps, rows)), encoding="utf-8")
    for url, page in list(pages.items())[:2]:
        (tmp_path / "pages" / f"{_key(url)}.json").write_text(page.model_dump_json(), "utf-8")
    got_rows, got_pages = r.load(tmp_path)
    assert len(got_rows) == 3 and set(got_pages) == {rows[0]["url"], rows[1]["url"]}


# ---- 0d --------------------------------------------------------------------------------------


def _row(**over: Any) -> dict[str, Any]:
    base = {"split": "test", "label": PHISH, "alive": True, "state": "SUSPICIOUS",
            "url_state": "UNKNOWN", "auto_open": True}  # fmt: skip
    return {**base, **over}


def test_page_only_catches_split_into_pass_fail_and_cannot_tell() -> None:
    rows = [
        _row(),  # passes the filter
        _row(auto_open=False, why_not="UNKNOWN with no sign"),
        _row(auto_open=False, url_state="BENIGN"),
        _row(auto_open=None),  # no stored filter result
        _row(url_state="ERROR"),
        _row(split="dev"),
        # not page-only catches
        _row(url_state="SUSPICIOUS"),  # the address already caught it
        _row(state="UNKNOWN"),  # the page did not flag it
        _row(alive=False),
        _row(label=LEGIT),
    ]
    out = r.page_only(rows, True)
    assert out["test"]["catches"] == 5 and out["dev"]["catches"] == 1 and out["all"]["catches"] == 6
    assert (out["test"]["pass"], out["test"]["fail"], out["test"]["cannot_tell"]) == (1, 2, 2)
    assert out["test"]["fail_why"] == {"UNKNOWN with no sign": 1, "BENIGN": 1}
    for half in r.HALVES:
        o = out[half]
        assert o["pass"] + o["fail"] + o["cannot_tell"] == o["catches"]


def test_without_the_popular_list_nothing_can_be_judged() -> None:
    out = r.page_only([_row(), _row(auto_open=False)], False)
    assert out["all"]["catches"] == out["all"]["cannot_tell"] == 2
    assert out["all"]["pass"] == out["all"]["fail"] == 0


def test_why_not_opened_names_the_failing_condition() -> None:
    assert r.why_not_opened("not a url at all") == "not a web address"
    assert r.why_not_opened("https://plain-site.test/") == "UNKNOWN with no sign"


# ---- the gate --------------------------------------------------------------------------------


def _write(out: Path, rep: dict[str, Any], md: bool = True) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "refusals.json").write_text(json.dumps(rep), encoding="utf-8")
    if md:
        (out / "refusals.md").write_text(r.render(rep), encoding="utf-8")


def test_check_prints_the_phrase_only_when_everything_holds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path, _report())
    assert r.check(tmp_path) == 0
    assert capsys.readouterr().out.strip() == "REFUSALS CLASSIFIED"


def test_check_fails_and_says_what(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path / "nomd", _report(), md=False)  # the markdown report is missing
    assert r.check(tmp_path / "nomd") == 1
    assert r.check(tmp_path / "nothing") == 1  # neither file

    small = tmp_path / "small"  # fewer than 150 classified
    _write(small, _report(40))
    assert r.check(small) == 1

    broken = _report()  # a class count that no longer adds up
    broken["runs"]["synthetic"]["groups"]["test"][PHISH]["classes"]["takedown"]["k"] += 1
    _write(tmp_path / "broken", broken)
    assert r.check(tmp_path / "broken") == 1

    no_0d = _report()  # 0d counts that do not add up to the catches
    no_0d["runs"]["synthetic"]["page_only"]["all"]["pass"] += 1
    _write(tmp_path / "no0d", no_0d)
    assert r.check(tmp_path / "no0d") == 1

    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "refusals.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "bad" / "refusals.md").write_text("x", encoding="utf-8")
    assert r.check(tmp_path / "bad") == 1

    out = capsys.readouterr().out
    assert "REFUSALS CLASSIFIED" not in out
    assert out.count("FAILED") >= 5


def test_the_report_holds_counts_not_text() -> None:
    rep = _report()
    md = r.render(rep)
    assert "https://" not in md and "host1.test" not in md and "boom" not in md
    assert "https://" not in json.dumps(rep)
