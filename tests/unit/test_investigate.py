"""DA5 1a: `python -m core.cli investigate`, the offline evidence dossier. The dossier must agree
with the engine to the point, rebuild its score from listed numbers, confirm every counterfactual
with the engine's own scorer, and say nothing the stored evidence does not."""

import hashlib
import itertools
import json
import random
import socket
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import deephelp as d
import pytest
from mailhelp import PHISH_LINK, eml, in_process, in_process_file, in_process_inspect

from core import hashlists, sandbox
from core.cli import main
from core.contracts import Confidence, ResponseAction, Signal, VerdictState
from core.detection.engine import _allowlisted, analyze_url
from core.detonate.judge import judge
from core.detonate.models import PageField, PageForm, PageReport, Tls
from core.email.engine import analyze_message
from core.files.engine import analyze_file
from core.investigate import (
    KEYS,
    SECTIONS,
    investigate,
    load_page_report,
    render_html,
    render_json,
    render_text,
    words,
)
from core.investigate.attribution import attribute, rebuild
from core.investigate.dossier import file_dossier, message_dossier
from core.learn.model import current as current_model
from core.risk.scoring import score
from core.urls import popular
from core.urls.parse import HostKind, UrlFlag
from rules.email.data import scoring as email_scoring
from rules.page import page_brands
from rules.url.data import official_domains, scoring

CORPUS = Path(__file__).parents[2] / "corpus" / "manifest.jsonl"
KNOWN = [
    "https://paypal.com@secure-check.test/login.php",
    "https://paypal.com@paypal.account-verify.test/login.php",
    "https://paypal-login.test/",
    "https://example.test/",
    "https://example.test:8080/",
    "http://203.0.113.5:8080/webmail/login",
    "https://www.paypal.com/",
    "https://accounts.google.com/signin",
    "https://xn--pypal-4ve.test/login",
    "hxxps://secure-account[.]test/verify",
    "https://login.microsoftonline.com.evil-host.test/oauth2/authorize?redirect_uri=https://x.test",
    "https://github.com/octocat/hello-world",
    "http://ex ample.test/",
    "javascript:alert(1)",
]


def _corpus_urls() -> list[str]:
    """One development-split address per category: the corpus's own fixtures (never the sealed
    reserve, and nothing is fetched)."""
    seen: set[str] = set()
    out = []
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        if e["split"] == "dev" and e["category"] not in seen:
            seen.add(e["category"])
            out.append(e["value"])
    return out


EICAR_SHA = hashlib.sha256(d.EICAR).hexdigest()
URLS = KNOWN + _corpus_urls()
assert len(URLS) >= 12


def _page(**over: Any) -> PageReport:
    base: dict[str, Any] = {
        "status": "ok", "http_status": 200, "final_url": "https://paypal-secure-login.test/signin",
        "title": "PayPal: Log in", "headings": ["PayPal"], "visited_at": 1_700_000_000,
        "forms": [
            PageForm(
                action="https://collector.test/post", method="post",
                fields=[PageField(type="email", hint="email"), PageField(type="password")],
            )
        ],
        "tls": Tls(valid_from=1_699_900_000, valid_to=1_707_000_000, issuer="Test CA"),
    }  # fmt: skip
    return PageReport(**{**base, **over})


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from _strings(v)


def _signals(dossier: dict[str, Any]) -> list[Signal]:
    return [Signal.model_validate(s) for s in dossier["verdict"]["signals"]]


@pytest.mark.parametrize("url", URLS, ids=[f"u{i:02d}" for i in range(len(URLS))])
def test_the_dossier_reproduces_the_engines_verdict_and_score(url: str) -> None:
    expected = analyze_url(url).verdict
    dossier = investigate(url)
    assert tuple(dossier) == KEYS
    assert tuple(dossier["sections"]) == SECTIONS
    v = dossier["verdict"]
    assert (v["state"], v["score"]) == (expected.state.value, expected.risk_score)
    assert [s["rule_id"] for s in v["signals"]] == [s.rule_id for s in expected.signals]
    assert v["confidence"] == expected.confidence.value
    if dossier["attribution"]["status"] == words.OK:
        assert dossier["attribution"]["matches_verdict"] is True
    else:
        assert v["reason"] is not None  # only an address that was never analysed has no breakdown


def _rebuilt_from_listed_numbers(dossier: dict[str, Any]) -> None:
    a = json.loads(render_json(dossier))["attribution"]  # only what a reader of the JSON has
    v = dossier["verdict"]
    assert rebuild(a) == (v["state"], v["score"])
    if v["score"] is not None and not a["certain_rules"]:
        assert round(a["risk_points"]) == v["score"]
    total = a["risk_points"]
    assert sum(s["points"] for s in a["signals"]) == pytest.approx(total, abs=1e-9)
    assert sum(c["points"] for c in a["categories"]) == pytest.approx(total, abs=1e-9)
    for c in a["categories"]:
        mine = [s["points"] for s in a["signals"] if s["category"] == c["category"]]
        assert sum(mine) == pytest.approx(c["points"], abs=1e-9)
        assert c["capped"] == min(c["noisy_or"], c["cap"])


def test_the_signal_contributions_rebuild_the_score() -> None:
    sections = [investigate(u) for u in URLS]
    sections.append(url_with_page())
    sections.append(message_dossier(eml(html=PHISH_LINK), "m.eml", in_process, in_process_inspect))
    sections.append(
        file_dossier("e.dat", len(d.EICAR), EICAR_SHA, d.EICAR, in_process_file)
    )  # exact identification: the score floor is part of the rebuild
    for dossier in sections:
        if dossier["attribution"]["status"] == words.OK:
            _rebuilt_from_listed_numbers(dossier)
    assert sections[-1]["attribution"]["certain_rules"]
    # a weight of exactly 1, caps that bite, the allowlist: random signal sets against the engine
    rng = random.Random(7)
    cats = [*scoring()["category_caps"], "unlisted"]
    for cfg, allow in itertools.product((scoring(), email_scoring()), (False, True)):
        for _ in range(150):
            sig = [
                Signal(
                    rule_id=f"r{i}", category=rng.choice(cats),
                    weight=rng.choice([0.0, 0.1, 0.3, 0.45, 0.5, 0.9, 1.0, rng.random()]),
                    description="x",
                )
                for i in range(rng.randint(0, 7))
            ]  # fmt: skip
            a = attribute(sig, allow, cfg)
            shown = score(sig, allow, cfg)
            assert rebuild(a) == (shown.state.value, shown.risk_score), sig


def url_with_page() -> dict[str, Any]:
    return investigate("https://paypal-secure-login.test/signin", page_report=_page())


# the three states a flagged address can be in, with the learned model off so they stay put
CASES = {
    "malicious": "https://paypal.com@paypal.account-verify.test/login.php",
    "suspicious": "https://paypal.com@secure-check.test/login.php",
    "unknown": "https://example.test:8080/",
    "benign": "https://www.paypal.com/",
}


@pytest.mark.usefixtures("no_learned_model")
@pytest.mark.parametrize("name", CASES)
def test_a_counterfactual_is_found_and_confirmed_by_rescoring(name: str) -> None:
    url = CASES[name]
    dossier = investigate(url)
    assert dossier["verdict"]["state"] == name.upper()
    start = analyze_url(url)
    signals = start.verdict.signals
    allow = start.url is not None and _allowlisted(start.url)
    cf = dossier["counterfactuals"]
    assert cf["baseline"] == {"state": name.upper(), "score": dossier["verdict"]["score"]}
    kinds = {i["kind"] for i in cf["items"]}
    assert kinds >= {words.REMOVE_ONE} or not signals
    assert (words.BELOW_SUSPICIOUS in kinds) == (name in ("malicious", "suspicious"))
    assert (words.BELOW_MALICIOUS in kinds) == (name == "malicious")
    assert (words.ADD_FOR_MALICIOUS in kinds) == (name == "suspicious")
    assert (words.ADD_FOR_SUSPICIOUS in kinds) == (name in ("unknown", "benign"))
    for item in cf["items"]:
        assert item["found"] and item["confirmed"]
        if item["added"]:
            goal = (
                VerdictState.MALICIOUS if "malicious" in item["kind"] else VerdictState.SUSPICIOUS
            )
            w = item["added"][0]

            def with_extra(weight: float) -> VerdictState:
                extra = Signal(rule_id="x", category="new", weight=weight, description="x")
                return score([*signals, extra], allow, scoring()).state

            reached = with_extra(w)
            assert reached is goal or (reached is VerdictState.MALICIOUS)  # SUSPICIOUS or beyond
            assert item["state"] == reached.value
            below = with_extra(round(w - 0.001, 3))
            assert below is not goal and below is not VerdictState.MALICIOUS or w == 0.001
            continue
        rest = [s for s in signals if s.rule_id not in item["removed"]]
        after = score(rest, allow, scoring())
        assert (item["state"], item["score"]) == (after.state.value, after.risk_score)
        if item["kind"] != words.REMOVE_ONE:
            n = len(item["removed"])
            flagged = (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
            for fewer in itertools.chain.from_iterable(
                itertools.combinations(signals, k) for k in range(n)
            ):
                kept = [s for s in signals if s not in fewer]
                smaller = score(kept, allow, scoring()).state
                if item["kind"] == words.BELOW_MALICIOUS:
                    assert smaller is VerdictState.MALICIOUS  # nothing smaller leaves MALICIOUS
                else:
                    assert smaller in flagged  # nothing smaller drops below SUSPICIOUS


def test_nothing_goes_online_unless_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opened: list[object] = []

    def refuse(*args: object, **kwargs: object) -> None:
        opened.append(args)
        raise RuntimeError("a socket was used")

    monkeypatch.setattr(socket.socket, "__init__", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(hashlists, "configure", lambda directory: None)
    mail, note = tmp_path / "m.eml", tmp_path / "note.txt"
    mail.write_bytes(eml(html=PHISH_LINK))
    note.write_bytes(b"just a note")
    saved = tmp_path / "page.json"
    saved.write_text(_page().model_dump_json(), encoding="utf-8")
    investigate(URLS[0])
    url_with_page()
    investigate(str(mail), mail_run=in_process, inspect_run=in_process_inspect)
    investigate(str(note), file_run=in_process_file)
    assert main(["investigate", URLS[0], "--json"]) == 0
    assert main(["investigate", URLS[0], "--page-report", str(saved)]) == 0
    capsys.readouterr()
    assert opened == []


def test_the_page_stage_reads_a_saved_detonation_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url = "https://paypal-secure-login.test/signin"
    page = _page()
    saved = tmp_path / "page.json"
    saved.write_text(page.model_dump_json(), encoding="utf-8")  # what eval/detonate keeps
    assert load_page_report(saved) == page
    start = analyze_url(url)
    judged = judge(start, page).verdict
    dossier = investigate(url, page_report=load_page_report(saved))
    v = dossier["verdict"]
    assert (v["state"], v["score"]) == (judged.state.value, judged.risk_score)
    assert dossier["engine"]["name"] == words.ENGINE_PAGE
    added = [s["rule_id"] for s in dossier["sections"]["page"]["facts"]["signals"]]
    assert added == [s.rule_id for s in judged.signals[len(start.verdict.signals) :]]
    assert {"page.brand_credential", "page.form_offsite"} <= set(added)
    assert dossier["attribution"]["matches_verdict"] is True
    assert dossier["sections"]["fetch"]["facts"]["final_url"] == page.final_url
    assert dossier["sections"]["fetch"]["facts"]["tls"]["issuer"] == "Test CA"
    brand = dossier["sections"]["brand"]["facts"]
    assert brand["claimed_brand"] == "PayPal" and brand["claimed_in"] == "title"
    assert brand["asks_credentials"] is True
    assert dossier["sections"]["redirect_chain"]["status"] == words.NOT_ASKED
    # the whole path through the command line
    monkeypatch.setattr(hashlists, "configure", lambda directory: None)
    assert main(["investigate", url, "--page-report", str(saved), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"]["score"] == judged.risk_score
    # a page that was not there adds nothing and says so; it is not a reason to call it safe
    dead = investigate(url, page_report=_page(status="dead", forms=[], title=""))
    assert dead["sections"]["page"]["note"] == words.PAGE_NOT_READ
    assert dead["verdict"]["state"] == analyze_url(url).verdict.state.value
    # the verdict report `detonate --json` prints has no page in it: a clear refusal
    wrong = tmp_path / "verdict.json"
    wrong.write_text(start.report().model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="holds no page content"):
        load_page_report(wrong)
    assert main(["investigate", url, "--page-report", str(wrong)]) == 2
    assert "holds no page content" in capsys.readouterr().err


def test_a_file_and_a_message_get_the_same_section_names(tmp_path: Path) -> None:
    mail, note = tmp_path / "m.eml", tmp_path / "note.txt"
    mail.write_bytes(eml(sender='"PayPal" <help@paypal-login.test>', html=PHISH_LINK))
    note.write_bytes(b"just a note")
    found = [
        investigate(URLS[0]),
        investigate(str(mail), mail_run=in_process, inspect_run=in_process_inspect),
        investigate(str(note), file_run=in_process_file),
        message_dossier(eml(), "m.eml", lambda raw: _unavailable()),
        file_dossier("e.dat", len(d.EICAR), EICAR_SHA, d.EICAR, in_process_file),
    ]
    assert [x["target"]["kind"] for x in found] == [
        words.URL, words.MESSAGE, words.FILE, words.MESSAGE, words.FILE
    ]  # fmt: skip
    statuses = {words.OK, words.NOT_APPLICABLE, words.NOT_ASKED, words.NOT_AVAILABLE}
    for x in found:
        assert tuple(x) == KEYS and tuple(x["sections"]) == SECTIONS
        assert all(set(s) == {"status", "note", "facts"} for s in x["sections"].values())
        assert {s["status"] for s in x["sections"].values()} <= statuses
        assert set(x["attribution"]) == set(found[0]["attribution"])
        assert set(x["counterfactuals"]) == set(found[0]["counterfactuals"])
        assert set(x["verdict"]) == set(found[0]["verdict"]) and x["limits"]
    message, plain, down, eicar = found[1], found[2], found[3], found[4]
    assert message["sections"]["anatomy"]["facts"]["summary"]["links"] >= 1
    assert message["sections"]["redirect_chain"]["status"] == words.NOT_ASKED
    assert message["sections"]["learned"]["status"] == words.NOT_APPLICABLE
    assert plain["sections"]["page"]["status"] == words.NOT_APPLICABLE
    assert plain["sections"]["intel"]["facts"]["hash_matches"] == []
    for x in (message, plain):
        assert x["attribution"]["matches_verdict"] is True
    # a message that could not be parsed is ERROR, with nothing to break down and no change tried
    assert (
        down["verdict"]["state"] == "ERROR"
        and down["attribution"]["status"] == words.NOT_APPLICABLE
    )
    assert down["counterfactuals"]["items"] == []
    assert down["sections"]["anatomy"]["status"] == words.NOT_AVAILABLE
    # the EICAR test file is exact identification on a built-in list, and the dossier says which
    assert eicar["verdict"]["state"] == "MALICIOUS" and eicar["verdict"]["score"] >= 95
    assert eicar["sections"]["intel"]["facts"]["hash_matches"]
    assert eicar["attribution"]["certain_rules"] and eicar["attribution"]["matches_verdict"]


def _unavailable() -> sandbox.Result:
    raise sandbox.SandboxUnavailable("not built")


def _evidence_text(*sources: Any) -> str:
    """Everything a dossier may quote: the input, the engine's output, rule data, contract words."""
    parts = [s for src in sources for s in _strings(src)]
    parts += [x.value for enum in (VerdictState, Confidence, ResponseAction, HostKind, UrlFlag)
              for x in enum]  # fmt: skip
    parts += [b.name for b in page_brands()] + [dom for b in page_brands() for dom in b.domains]
    parts += [*official_domains(), *official_domains().values()]
    model = current_model()
    return "\n".join(parts + ([model.version] if model else []))


def test_only_stored_evidence_is_named(tmp_path: Path) -> None:
    popular.use(frozenset({"example.test"}))  # so `established` has something to say
    mail = eml(sender='"PayPal" <help@paypal-login.test>', html=PHISH_LINK)
    page = _page()
    cases: list[tuple[dict[str, Any], list[Any]]] = []
    for url in (URLS[0], URLS[1], "https://example.test/a?b=1&c=%C3%A9#f", URLS[12]):
        a = analyze_url(url)
        cases.append((investigate(url), [url, a.model_dump(mode="json")]))
    start = analyze_url("https://paypal-secure-login.test/signin")
    cases.append((
        investigate("https://paypal-secure-login.test/signin", page_report=page),
        [page.model_dump(mode="json"), judge(start, page).model_dump(mode="json"),
         start.model_dump(mode="json")],
    ))  # fmt: skip
    m = analyze_message(mail, run=in_process, inspect_run=in_process_inspect)
    cases.append((message_dossier(mail, "m.eml", in_process, in_process_inspect),
                  [m.model_dump(mode="json"), "m.eml"]))  # fmt: skip
    f = analyze_file("e.dat", len(d.EICAR), EICAR_SHA, d.EICAR, run=in_process_file)
    cases.append((file_dossier("e.dat", len(d.EICAR), EICAR_SHA, d.EICAR, in_process_file),
                  [f.model_dump(mode="json"), "e.dat"]))  # fmt: skip
    vocabulary = words.vocabulary()
    for dossier, sources in cases:
        evidence = _evidence_text(*sources)
        # the learned model's own words for the tokens that pushed the score
        evidence += "\n" + "\n".join(dossier["sections"]["learned"]["facts"].get("pushed_by", []))
        for leaf in _strings(dossier):
            assert leaf in vocabulary or leaf in evidence, f"not stored evidence: {leaf!r}"


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.attrs: set[str] = set()
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        self.attrs |= {a for a, _ in attrs}

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def test_the_html_dossier_escapes_hostile_text() -> None:
    hostile = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    url = f"https://paypal.com@secure-check.test/{hostile}?{hostile}=1&‮=rlo\x1b[31m"
    page = _page(
        final_url="https://secure-check.test/x", title=hostile, headings=[hostile, "PayPal"],
        forms=[PageForm(action="https://collector.test/p", method="post",
                        fields=[PageField(type="password", hint=hostile)])],
        chain=["https://" + hostile.replace("<", "%3C")],
    )  # fmt: skip
    for dossier in (investigate(url), investigate(url, page_report=page)):
        page_html = render_html(dossier)
        assert "<script" not in page_html.lower() and "<img" not in page_html.lower()
        tags = _Tags()
        tags.feed(page_html)
        assert tags.tags <= {
            "html", "head", "meta", "title", "style", "body", "h1", "h2", "p", "span", "section",
            "dl", "dt", "dd", "table", "tr", "th", "td", "ul", "li",
        }  # fmt: skip
        assert not {a for a in tags.attrs if a.startswith("on") or a in ("src", "href", "srcset")}
        text = "".join(tags.text)
        assert hostile in text  # shown, as text
        assert "<U+202E>" in text and "‮" not in page_html  # the bidi override is made visible
        assert "Content-Security-Policy" in page_html and "default-src 'none'" in page_html
        assert "\x1b" not in page_html and "\x1b" not in render_text(dossier)
        assert "\x1b" not in render_json(dossier) and json.loads(render_json(dossier))


def test_the_command_writes_the_html_file_and_prints_json_keys_in_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hashlists, "configure", lambda directory: None)
    out = tmp_path / "dossier.html"
    code = main(["investigate", URLS[0], "--json", "--html", str(out)])
    printed, err = capsys.readouterr()
    assert code == 0 and "wrote" in err
    assert printed.index('"attribution"') < printed.index('"counterfactuals"')
    assert tuple(json.loads(printed)) == KEYS
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert main(["investigate", URLS[0]]) == 0
    assert capsys.readouterr().out.startswith(("MALICIOUS", "SUSPICIOUS"))
    note = tmp_path / "n.txt"
    note.write_bytes(b"x")
    assert main(["investigate", str(note), "--page-report", str(out)]) == 2
    capsys.readouterr()
