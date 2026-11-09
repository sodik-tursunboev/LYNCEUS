# ruff: noqa: E501  (the sample macros are long literal lines)
"""The bounded VBA evaluator (core/sandbox/guest/vbaeval.py): it rebuilds the strings a macro's own
decoder code produces, never performs anything real, and stops on every hostile construct.

All macros here are inert test text written for this file."""

import random
import re
import time
from pathlib import Path

import pytest
import vbaeval


def built(source: str) -> list[str]:
    return vbaeval.evaluate(source).strings


def hexed(text: str) -> str:
    return text.encode().hex().upper()


HEX_DECODER = """
Function Dec(s As String) As String
  Dim i As Long, r As String
  For i = 1 To Len(s) Step 2
    r = r & Chr(Val("&H" & Mid(s, i, 2)))
  Next i
  Dec = r
End Function
"""


def test_a_hex_decoder_function_reveals_the_command_it_hides() -> None:
    src = (
        HEX_DECODER
        + f'Sub AutoOpen()\n  Shell Dec("{hexed("powershell -nop -w hidden")}"), 0\nEnd Sub\n'
    )
    assert "powershell -nop -w hidden" in built(src)


def test_a_decoder_called_through_variables_and_concatenation() -> None:
    parts = [hexed("cmd /c "), hexed("certutil -urlcache")]
    src = HEX_DECODER + (
        "Sub Document_Open()\n"
        f'  Dim a As String, b As String\n  a = Dec("{parts[0]}")\n  b = Dec("{parts[1]}")\n'
        '  CreateObject("WScript.Shell").Run a & b\nEnd Sub\n'
    )
    assert "cmd /c certutil -urlcache" in built(src)


def test_an_xor_loop_over_an_array() -> None:
    key = 23
    codes = ", ".join(str(ord(c) ^ key) for c in "mshta http")
    src = (
        "Sub AutoOpen()\n  Dim k, i, r\n"
        f"  k = Array({codes})\n"
        f"  For i = 0 To UBound(k)\n    r = r & Chr(k(i) Xor {key})\n  Next\n"
        "  Shell r\nEnd Sub\n"
    )
    assert "mshta http" in built(src)


def test_chr_arithmetic_reverse_and_replace() -> None:
    src = (
        "Sub Workbook_Open()\n"
        '  a = StrReverse("llehsrewop")\n'
        '  b = Replace("pXoXwXeXrXsXhXeXlXl", "X", "")\n'
        '  c = Chr(110 + 1) & Chr$(&H6F) & Chr(Asc("a") + 15) & Chr(33)\n'
        "End Sub\n"
    )
    got = built(src)
    assert "powershell" in got and "oop!" in got


def test_a_value_hidden_behind_a_check_nobody_can_decide_is_still_seen() -> None:
    src = (
        "Sub AutoOpen()\n"
        '  If Environ("USERNAME") <> "analyst" Then\n'
        '    cmd = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & "shell"\n'
        "  End If\nEnd Sub\n"
    )
    assert "powershell" in built(src)


def test_select_case_while_and_do_loops() -> None:
    src = (
        'Function F(n)\n  Select Case n\n    Case 1: F = "one!"\n    Case Else: F = "many"\n  End Select\nEnd Function\n'
        "Sub AutoOpen()\n  i = 0\n  Do While i < 3\n    s = s & F(i)\n    i = i + 1\n  Loop\n"
        "  Shell s\nEnd Sub\n"
    )
    assert "manyone!many" in built(src)


def test_user_functions_parameters_and_exit_for() -> None:
    src = (
        "Function Twice(x)\n  Twice = x & x\nEnd Function\n"
        'Sub AutoOpen()\n  For i = 1 To 10\n    r = Twice("ab")\n    If i = 2 Then Exit For\n  Next\nEnd Sub\n'
    )
    assert "abab" in built(src)


def test_the_unknown_call_is_not_performed_only_its_text_is_noted() -> None:
    src = (
        'Sub AutoOpen()\n  Shell "calc.exe " & "/unlikely", 1\n'
        '  CreateObject("Some." & "Object").Run "x y " & "z w"\nEnd Sub\n'
    )
    got = built(src)
    assert {"calc.exe /unlikely", "x y z w", "Some.Object"} <= set(got)


def test_the_evaluator_has_no_way_to_reach_the_machine() -> None:
    source = Path(vbaeval.__file__).read_text(encoding="utf-8")
    imports = set(re.findall(r"^\s*(?:import|from)\s+([\w.]+)", source, re.MULTILINE))
    assert imports <= {"math", "re", "time", "collections.abc", "dataclasses", "typing", "limits"}
    for word in ("open(", "subprocess", "socket", "ctypes", "os.", "eval(", "exec(", "__import__"):
        assert word not in source


@pytest.mark.parametrize(
    "src",
    [
        'Sub AutoOpen()\n  Do\n    x = x & "a"\n  Loop\nEnd Sub\n',
        "Sub AutoOpen()\n  For i = 1 To 2000000000\n    x = i\n  Next\nEnd Sub\n",
        "Sub AutoOpen()\n  While True\n  Wend\nEnd Sub\n",
        "Function F()\n  F = F()\nEnd Function\nSub AutoOpen()\n  x = F()\nEnd Sub\n",
        "Sub A()\n  B\nEnd Sub\nSub B()\n  A\nEnd Sub\nSub AutoOpen()\n  A\nEnd Sub\n",
        'Sub AutoOpen()\n  s = "aaaa"\n  For i = 1 To 60\n    s = s & s\n  Next\nEnd Sub\n',
        'Sub AutoOpen()\n  Dim a(2000000000)\n  x = Space(2000000000)\n  y = String(2000000000, "z")\nEnd Sub\n',
        'Sub AutoOpen()\n  x = 2 ^ 99999\n  y = 1 / 0\n  z = CLng("not a number")\nEnd Sub\n',
    ],
)
def test_hostile_constructs_end_quickly_and_within_bounds(src: str) -> None:
    started = time.monotonic()
    result = vbaeval.evaluate(src)
    assert time.monotonic() - started < 8.0
    assert all(len(s) <= 16 * 1024 for s in result.strings)
    assert len(result.strings) <= 400


def test_endless_loops_report_that_a_bound_was_hit() -> None:
    assert vbaeval.evaluate("Sub AutoOpen()\n  Do\n    x = x + 1\n  Loop\nEnd Sub\n").truncated


def test_parentheses_nested_far_too_deep_do_not_crash() -> None:
    deep = "(" * 4000 + "1" + ")" * 4000
    assert vbaeval.evaluate(f"Sub AutoOpen()\n  x = {deep}\nEnd Sub\n").strings == []


def test_garbage_never_raises() -> None:
    rng = random.Random(7)
    pieces = [
        "Sub",
        "End Sub",
        "If",
        "Then",
        "Else",
        "For",
        "Next",
        "(",
        ")",
        '"',
        "&",
        ":=",
        "Chr(",
        "_",
        "'",
        "Dim",
        "x",
        "=",
        "1",
        "\n",
    ]
    for _ in range(300):
        text = " ".join(rng.choice(pieces) for _ in range(rng.randint(1, 60)))
        vbaeval.evaluate(text)
    for _ in range(50):
        vbaeval.evaluate(rng.randbytes(2000).decode("latin-1"))


def test_strings_already_written_in_the_source_are_not_reported_as_revealed() -> None:
    assert built('Sub AutoOpen()\n  x = "plain text here"\nEnd Sub\n') == []


def test_line_continuations_comments_and_single_line_if() -> None:
    src = (
        "Sub AutoOpen()\n"
        '  a = "pow" & _\n      "ersh" \' a comment with "quotes\n'
        '  If 1 = 1 Then b = a & "ell" Else b = "no"\n'
        "End Sub\n"
    )
    assert "powershell" in built(src)
