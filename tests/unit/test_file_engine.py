"""The file engine: a downloaded file judged by the attachment rules, never BENIGN, and every
failure a stated verdict. The sandbox is replaced by the in-process guest scanner."""

import hashlib
import json
from collections.abc import Callable
from typing import Any

import filehelp as fh
import pytest
from mailhelp import in_process_file, ok_result

from core import sandbox
from core.contracts import ResponseAction, VerdictState
from core.files.engine import ENGINE_VERSION, FileAnalysis, analyze_file, wants_reputation
from core.intel.filerep import FileRep

EXE = b"MZ\x90\x00" + b"\x00" * 60
RLO = chr(0x202E)


def judge(name: str, data: bytes, **kw: Any) -> FileAnalysis:
    return analyze_file(
        name, len(data), hashlib.sha256(data).hexdigest(), data, run=in_process_file, **kw
    )


def rules(a: FileAnalysis) -> set[str]:
    return {s.rule_id for s in a.report.verdict.signals}


def state(a: FileAnalysis) -> VerdictState:
    return a.report.verdict.state


# ---- ordinary files ------------------------------------------------------------------------------


def test_a_plain_file_is_unknown_never_benign() -> None:
    a = judge("notes.txt", b"just words")
    v = a.report.verdict
    assert (v.state, v.risk_score, a.report.reason, a.report.inspected) == (
        VerdictState.UNKNOWN, None, None, True,
    )  # fmt: skip
    assert "not evidence of safety" in v.explanation and v.engine_version == ENGINE_VERSION
    assert v.applied_response is ResponseAction.NONE


def test_a_document_that_is_what_it_says_is_not_flagged() -> None:
    assert state(judge("report.pdf", fh.PDF_PLAIN)) is VerdictState.UNKNOWN
    assert state(judge("photo.png", fh.blank_png())) is VerdictState.UNKNOWN
    assert state(judge("files.zip", fh.make_zip({"a.txt": b"hi"}))) is VerdictState.UNKNOWN


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("setup.scr", EXE, {"email.dangerous_attachment"}),
        ("invoice.pdf.exe", EXE, {"email.double_extension", "email.dangerous_attachment"}),
        ("invoice.pdf", EXE, {"email.attachment_type_mismatch", "email.dangerous_attachment"}),
        ("budget.xlsm", b"PK\x03\x04" + b"\x00" * 30, {"email.macro_attachment"}),
        (f"invoice{RLO}fdp.exe", EXE, {"email.rtl_filename", "email.dangerous_attachment"}),
        ("page.html", b"<html><body>x</body></html>", {"email.html_attachment"}),
    ],
)
def test_the_attachment_rules_apply_to_a_file(name: str, data: bytes, expected: set[str]) -> None:
    a = judge(name, data)
    assert expected <= rules(a), (name, rules(a))
    assert state(a) in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)


def test_archive_and_pdf_contents_are_opened_in_the_sandbox() -> None:
    assert "email.archive_contents_dangerous" in rules(judge("p.zip", fh.make_zip({"x.scr": b"x"})))
    assert "email.archive_bomb" in rules(judge("big.zip", fh.zip_bomb(300)))
    assert "email.pdf_javascript" in rules(judge("a.pdf", fh.PDF_JS))
    assert "email.pdf_launch_action" in rules(judge("a.pdf", fh.PDF_LAUNCH))
    assert "email.qr_code_link" in rules(judge("c.png", fh.qr_png("https://phish-site.test/x")))


def test_a_page_that_builds_and_saves_a_file_is_flagged() -> None:
    page = (
        b'<html><script>var b = new Blob([atob("QUJD")]); var a = document.createElement("a");'
        b'a.href = URL.createObjectURL(b); a.download = "x.zip"; a.click();</script></html>'
    )
    assert "email.html_smuggling" in rules(judge("invoice.html", page))


def test_urls_inside_a_pdf_go_through_the_url_engine_and_are_kept_as_hashes() -> None:
    pdf = fh.pdf_with_uris("https://paypal-login.test/login.php?email=jane%40example.test")
    a = judge("statement.pdf", pdf)
    assert {"url.combosquat", "url.prefilled_identity"} <= rules(a)
    assert (
        a.urls
        and a.urls[0].host == "paypal-login.test"
        and "http" not in a.urls[0].model_dump_json()
    )


def test_a_malicious_file_recommends_quarantine_but_applies_nothing() -> None:
    pdf = fh.make_pdf(
        "/OpenAction 4 0 R",
        [
            "<< /S /Launch /F (cmd.exe) >>",
            "<< /S /JavaScript /JS (x) >>",
            "<< /S /URI /URI (https://paypal-login.test/login.php?email=jane%40example.test) >>",
        ],
    )
    bad = judge("a.pdf", pdf).report.verdict
    assert bad.state is VerdictState.MALICIOUS
    assert (bad.recommended_response, bad.applied_response) == (
        ResponseAction.QUARANTINE,
        ResponseAction.NONE,
    )
    mild = judge("invoice.pdf.exe", EXE).report.verdict
    assert (
        mild.state is VerdictState.SUSPICIOUS and mild.recommended_response is ResponseAction.WARN
    )
    assert mild.applied_response is ResponseAction.NONE


# ---- downloaded installers (DA1) -----------------------------------------------------------------
# On this computer all 6 files the agent flagged were installers flagged by being a program alone.


@pytest.mark.parametrize("name", ["setup.exe", "Tool-Installer.msi"])
def test_an_installer_alone_is_unknown_but_keeps_its_sign(name: str) -> None:
    a = judge(name, EXE)
    assert state(a) is VerdictState.UNKNOWN
    sign = next(s for s in a.report.verdict.signals if s.rule_id == "email.dangerous_attachment")
    assert sign.weight == pytest.approx(0.3) and "installer" in sign.description


def test_an_installer_from_a_site_that_looks_like_phishing_is_flagged() -> None:
    a = judge("setup.exe", EXE, origin_host="paypal-login-secure.test")
    assert "file.origin_flagged" in rules(a)
    assert state(a) in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    origin = next(s for s in a.report.verdict.signals if s.rule_id == "file.origin_flagged")
    assert "paypal-login-secure.test" in origin.description and origin.category == "origin"


def test_an_installer_from_an_ordinary_site_stays_unknown() -> None:
    a = judge("setup.exe", EXE, origin_host="downloads.example.test")
    assert "file.origin_flagged" not in rules(a)
    assert state(a) is VerdictState.UNKNOWN


@pytest.mark.parametrize(
    "name",
    ["invoice.pdf.exe", f"invoice{RLO}fdp.exe", "setup.scr", "update.hta"],
)
def test_disguised_programs_and_rare_runnable_types_are_still_flagged(name: str) -> None:
    data = EXE if not name.endswith(".hta") else b"<html><script>x</script></html>"
    a = judge(name, data)
    assert state(a) in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS), (name, rules(a))


def test_a_program_named_as_a_document_keeps_the_full_weight() -> None:
    a = judge("invoice.pdf", EXE)
    sign = next(s for s in a.report.verdict.signals if s.rule_id == "email.dangerous_attachment")
    assert sign.weight == pytest.approx(0.75)


# ---- what VirusTotal's engines say about the hash (DA2) ----------------------------------------


def seen_by(flagged: int, harmless: int = 60) -> FileRep:
    return FileRep(flagged, 0, harmless, 10, None)


def test_many_engines_make_a_file_malicious() -> None:
    a = judge("setup.exe", EXE, reputation=seen_by(25))
    assert state(a) is VerdictState.MALICIOUS and "file.vt_known_bad" in rules(a)
    assert a.report.verdict.recommended_response is ResponseAction.QUARANTINE
    sign = next(s for s in a.report.verdict.signals if s.rule_id == "file.vt_known_bad")
    assert "25 of 95 engines" in sign.description and "setup.exe" not in sign.description


def test_a_few_engines_make_a_file_suspicious() -> None:
    a = judge("setup.exe", EXE, reputation=seen_by(5))
    assert state(a) is VerdictState.SUSPICIOUS and "file.vt_flagged" in rules(a)
    assert "file.vt_known_bad" not in rules(a)


def test_one_or_two_engines_never_flag_a_file_alone() -> None:
    for flagged in (1, 2):
        a = judge("setup.exe", EXE, reputation=seen_by(flagged))
        assert "file.vt_weak" in rules(a) and state(a) is VerdictState.UNKNOWN
    a = judge("notes.txt", b"just words", reputation=seen_by(2))
    assert state(a) is VerdictState.UNKNOWN


def test_no_reputation_changes_nothing() -> None:
    plain = judge("setup.exe", EXE)
    for rep in (None, seen_by(0, harmless=70)):  # not asked or no answer; a clean report
        a = judge("setup.exe", EXE, reputation=rep)
        assert (state(a), rules(a), a.report.verdict.risk_score) == (
            state(plain), rules(plain), plain.report.verdict.risk_score,
        )  # fmt: skip
        assert state(a) is not VerdictState.BENIGN


def test_a_file_that_could_not_be_opened_is_still_identified_by_many_engines() -> None:
    def unavailable(_d: bytes) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("not built")

    sha = hashlib.sha256(EXE).hexdigest()
    a = analyze_file("setup.exe", len(EXE), sha, EXE, run=unavailable, reputation=seen_by(25))
    assert state(a) is VerdictState.MALICIOUS
    b = analyze_file("setup.exe", len(EXE), sha, EXE, run=unavailable, reputation=seen_by(2))
    assert (state(b), b.report.reason) == (VerdictState.ERROR, "sandbox_unavailable")


@pytest.mark.parametrize(
    ("name", "asked"),
    [
        ("setup.exe", True), ("Tool.MSI", True), ("run.ps1", True), ("a.lnk", True),
        ("disk.iso", True), ("pack.zip", True), ("macro.docm", True),
        (f"evil{RLO}.exe", True), ("report.pdf", False), ("photo.png", False),
        ("notes.txt", False), ("letter.docx", False), ("noextension", False),
    ],
)  # fmt: skip
def test_only_program_like_names_are_asked_about(name: str, asked: bool) -> None:
    assert wants_reputation(name) is asked


# ---- no bytes ------------------------------------------------------------------------------------


def test_without_bytes_the_name_and_reported_type_still_count() -> None:
    a = analyze_file("setup.scr", 4096, "ab" * 32, None, claimed_magic="exe")
    assert "email.dangerous_attachment" in rules(a)
    assert a.report.inspected is False and "not opened" in a.report.verdict.explanation


def test_an_invented_type_is_ignored_and_a_big_inspectable_file_is_reported_as_skipped() -> None:
    a = analyze_file("x.dat", 10, "cd" * 32, None, claimed_magic="not-a-type")
    assert a.report.verdict.state is VerdictState.UNKNOWN and not a.report.files
    b = analyze_file("big.pdf", 50_000_000, "ef" * 32, None, claimed_magic="pdf")
    assert "email.file_inspection_incomplete" in rules(b)
    assert [f.status for f in b.report.files] == ["skipped"]


# ---- failures are verdicts -----------------------------------------------------------------------


def test_a_file_that_changed_after_it_was_hashed_is_unknown_not_judged() -> None:
    a = analyze_file("a.txt", 5, "00" * 32, b"hello", run=in_process_file)
    assert (state(a), a.report.reason) == (VerdictState.UNKNOWN, "changed_while_reading")
    assert a.sha256 == hashlib.sha256(b"hello").hexdigest()  # the core's own hash


@pytest.mark.parametrize("bad", ["", "zz", "A" * 10, "1" * 63])
def test_no_usable_hash_and_no_bytes_is_unknown(bad: str) -> None:
    a = analyze_file("a.txt", 5, bad, None)
    assert (state(a), a.report.reason) == (VerdictState.UNKNOWN, "no_hash")


def test_a_file_over_the_limit_is_unknown_and_the_sandbox_is_not_started() -> None:
    def never(_d: bytes) -> sandbox.Result:
        raise AssertionError("must not start a sandbox")

    big = b"a" * (16 * 1024 * 1024)
    a = analyze_file("big.bin", len(big), hashlib.sha256(big).hexdigest(), big, run=never)
    assert (state(a), a.report.reason) == (VerdictState.UNKNOWN, "too_large")


def test_sandbox_failures_are_stated_not_ignored() -> None:
    def unavailable(_d: bytes) -> sandbox.Result:
        raise sandbox.SandboxUnavailable("not built")

    def broken(_d: bytes) -> sandbox.Result:
        raise OSError("CreateProcess failed")

    for run, want in ((unavailable, "sandbox_unavailable"), (broken, "sandbox_error")):
        a = analyze_file("a.bin", 3, "", b"abc", run=run)
        assert (state(a), a.report.reason) == (VerdictState.ERROR, want)
        assert a.report.verdict.risk_score is None
    for why in ("timeout", "cpu_limit", "memory_limit", "output_limit", "crashed"):
        a = analyze_file("a.bin", 3, "", b"abc", run=lambda _d, w=why: ok_result(b"", w))
        assert (state(a), a.report.reason) == (VerdictState.UNKNOWN, f"parser_{why}")


HOSTILE: dict[str, bytes | dict[str, Any]] = {
    "not json": b"nope",
    "empty": {},
    "ok only": {"ok": True},
    "error and file": {"ok": True, "file": {"kind": "none"}, "error": "memory"},
    "unknown kind": {"ok": True, "file": {"kind": "exe"}},
    "extra field": {"ok": True, "file": {"kind": "none"}, "extra": 1},
    "unknown magic": {"ok": True, "magic": "elfx", "file": {"kind": "none"}},
    "bad html": {"ok": True, "file": {"kind": "none"}, "html": {"forms": "many"}},
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_worker_reply_is_an_error_verdict(name: str) -> None:
    payload = HOSTILE[name]
    out = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    a = analyze_file("a.bin", 3, "", b"abc", run=lambda _d: ok_result(out))
    assert state(a) is VerdictState.ERROR and a.report.reason == "worker_output_invalid"


def test_the_worker_saying_it_gave_up_is_unknown() -> None:
    a = analyze_file("a.bin", 3, "", b"abc", run=lambda _d: ok_result(b'{"error": "memory"}'))
    assert (state(a), a.report.reason) == (VerdictState.UNKNOWN, "memory")


# ---- hostile names and privacy -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "a\x00b.exe",
        "..\\..\\evil.exe",
        "C:\\Users\\x\\a.exe",
        "x" * 1000 + ".exe",
        f"{RLO}exe.txt",
        "",
        "\n",
    ],
)
def test_odd_names_are_handled_and_flagged_never_fatal(name: str) -> None:
    a = judge(name, EXE)
    assert state(a) in (VerdictState.UNKNOWN, VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    assert a.report.reason is None


def test_findings_name_facts_not_the_file_name_or_its_contents() -> None:
    zipped = fh.make_zip({"ENTRYMARK.pdf.exe": EXE})
    a = judge("FILEMARK.zip", zipped, origin_host="origin-site.test")
    said = " ".join(
        [a.report.verdict.explanation]
        + [s.description for s in a.report.verdict.signals]
        + [e.summary for e in a.report.evidence]
        + [fact for f in a.report.files for fact in (f.kind, f.status, *f.facts)]
    )
    assert rules(a)
    for marker in ("FILEMARK", "ENTRYMARK"):
        assert marker not in said, marker


@pytest.mark.parametrize(
    ("given", "kept"),
    [
        ("Origin-Site.TEST", "origin-site.test"),
        ("a.example.com.", "a.example.com"),
        ("bad host", None),
        ("http://x.test/", None),
        ("", None),
        ("x" * 300 + ".com", None),
        (None, None),
    ],
)
def test_the_origin_host_is_kept_only_if_it_is_a_host(given: str | None, kept: str | None) -> None:
    assert judge("a.txt", b"x", origin_host=given).origin_host == kept


def test_the_same_file_gives_the_same_verdict() -> None:
    def shape(a: FileAnalysis) -> tuple[Any, ...]:
        v = a.report.verdict
        return v.state, v.risk_score, [(s.rule_id, s.weight) for s in v.signals], v.explanation

    run: Callable[[], FileAnalysis] = lambda: judge("invoice.pdf.exe", EXE)  # noqa: E731
    assert shape(run()) == shape(run())
