"""Excel 4.0 (XLM) macro sheets stored as XML (xl/macrosheets/sheetN.xml in an .xlsm file). Standard
library only; runs INSIDE the sandbox on hostile input.

An XLM macro is not VBA: it is a column of formulas (=EXEC(...), =CALL("URLDownloadToFile", ...),
=FORMULA(...) that writes more formulas) that Excel runs from top to bottom, usually on a hidden
sheet, usually with its words spread over many cells and rebuilt with CHAR() and "&". Nothing is run
here: the few functions that build text (CHAR, &, CONCATENATE, MID, LEFT, RIGHT, UPPER, LOWER) and
cell references are evaluated, every other function call is only noted, and what the formulas spell
out is searched like any script.
"""

import html
import re
from typing import Any

import contentscan
from limits import MAX_CONTENT_BYTES

_CELL = re.compile(r'<c\b[^>]*?\br="([A-Z]{1,3}[0-9]{1,6})"[^>]*?(?:/>|>(.*?)</c>)', re.DOTALL)
_FORMULA = re.compile(r"<f\b[^>]*>(.*?)</f>", re.DOTALL)
_VALUE = re.compile(r"<v>(.*?)</v>|<t\b[^>]*>(.*?)</t>", re.DOTALL)
_TOKEN = re.compile(
    r"""\s*(?:(?P<str>"(?:[^"]|"")*")|(?P<num>\d+(?:\.\d+)?)"""
    r"""|(?P<ref>\$?[A-Z]{1,3}\$?\d{1,6})(?![\w(])|(?P<name>[A-Za-z_][\w.]*)(?=\s*\()"""
    r"""|(?P<op>[&(),+]))"""
)
_MAX_CELLS = 20_000
_MAX_DEPTH = 40
# functions whose use is the finding, whatever they are given
_EXEC = {"EXEC", "RUN"}
_WRITERS = {"FORMULA", "FORMULA.FILL", "FORMULA.ARRAY", "SET.VALUE"}


class _Sheet:
    def __init__(self, formulas: dict[str, str], values: dict[str, str]) -> None:
        self.formulas, self.values = formulas, values
        self.cache: dict[str, str] = {}
        self.calls: list[tuple[str, list[str]]] = []
        self.built: list[str] = []
        self.busy: set[str] = set()

    def cell(self, ref: str, depth: int) -> str:
        ref = ref.replace("$", "")
        if ref in self.cache:
            return self.cache[ref]
        if ref in self.busy or depth > _MAX_DEPTH:
            return ""
        if ref not in self.formulas:
            return self.values.get(ref, "")
        self.busy.add(ref)
        try:
            out = self.run(self.formulas[ref], depth + 1)
        finally:
            self.busy.discard(ref)
        self.cache[ref] = out
        return out

    def run(self, text: str, depth: int) -> str:
        tokens: list[tuple[str, str]] = []
        pos = 0
        text = text.lstrip("= ")
        while pos < len(text) and len(tokens) < 4000:
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                break
            pos = m.end()
            tokens.append((m.lastgroup or "", m.group(m.lastgroup or "")))
        i = 0

        def expr() -> str:
            nonlocal i
            value = term()
            while i < len(tokens) and tokens[i] in (("op", "&"), ("op", "+")):
                i += 1
                value += term()
            return value

        def term() -> str:
            nonlocal i
            if i >= len(tokens):
                return ""
            kind, val = tokens[i]
            i += 1
            if kind == "str":
                return val[1:-1].replace('""', '"')
            if kind == "num":
                return val
            if kind == "ref":
                return self.cell(val, depth)
            if (kind, val) == ("op", "("):
                inner = expr()
                if i < len(tokens) and tokens[i] == ("op", ")"):
                    i += 1
                return inner
            if kind == "name":
                i += 1  # the "("
                args: list[str] = []
                while i < len(tokens) and tokens[i] != ("op", ")"):
                    args.append(expr())
                    if i < len(tokens) and tokens[i] == ("op", ","):
                        i += 1
                if i < len(tokens):
                    i += 1
                return self.apply(val.upper(), args)
            return ""

        return expr()

    def apply(self, name: str, args: list[str]) -> str:
        try:
            if name == "CHAR":
                n = int(float(args[0]))
                return chr(n) if 0 < n < 256 else ""
            if name == "CONCATENATE":
                return "".join(args)
            if name in ("UPPER", "LOWER"):
                return args[0].upper() if name == "UPPER" else args[0].lower()
            if name == "MID":
                start = int(float(args[1]))
                return args[0][start - 1 : start - 1 + int(float(args[2]))]
            if name == "LEFT":
                return args[0][: int(float(args[1])) if len(args) > 1 else 1]
            if name == "RIGHT":
                n = int(float(args[1])) if len(args) > 1 else 1
                return args[0][len(args[0]) - n :] if n > 0 else ""
        except (ValueError, IndexError):
            return ""
        self.calls.append((name, args))
        for a in args:
            if len(a) >= 4:
                self.built.append(a)
        return ""


def excerpt(data: bytes, limit: int = 6000) -> str:
    """The sheet's formulas, in order, with what they spell out, as plain text for a reader."""
    xml = data[:MAX_CONTENT_BYTES].decode("utf-8", "replace")
    formulas: dict[str, str] = {}
    for n, m in enumerate(_CELL.finditer(xml)):
        if n >= _MAX_CELLS:
            break
        f = _FORMULA.search(m.group(2) or "")
        if f:
            formulas[m.group(1)] = html.unescape(f.group(1))
    lines = [f"{ref}: ={text[:300]}" for ref, text in list(formulas.items())[:150]]
    return "\n".join(lines)[:limit]


def scan_xlm_xml(data: bytes, auto: bool = False, hidden: bool = False) -> dict[str, Any]:
    """Scan one macro sheet. `auto`: the workbook has an Auto_Open name. `hidden`: it is hidden."""
    st = contentscan._State()  # noqa: SLF001
    xml = data[:MAX_CONTENT_BYTES].decode("utf-8", "replace")
    formulas: dict[str, str] = {}
    values: dict[str, str] = {}
    for n, m in enumerate(_CELL.finditer(xml)):
        if n >= _MAX_CELLS:
            st.truncated = True
            break
        ref, body = m.group(1), m.group(2) or ""
        f = _FORMULA.search(body)
        if f:
            formulas[ref] = html.unescape(f.group(1))
        elif v := _VALUE.search(body):
            values[ref] = html.unescape(v.group(1) or v.group(2) or "")
    sheet = _Sheet(formulas, values)
    for ref in sorted(formulas, key=lambda r: (int(re.sub(r"\D", "", r)), r)):
        sheet.cell(ref, 0)
    st.add("xlm_macro")
    st.add("macro_code")
    if hidden:
        st.add("xlm_hidden")
    if auto:
        st.add("autoexec")
    names = {name for name, _ in sheet.calls}
    if names & _EXEC:
        st.add("exec_shell", sum(1 for n, _ in sheet.calls if n in _EXEC))
    if names & _WRITERS:  # formulas that write more formulas: code that rewrites itself
        st.add("execute_dynamic", sum(1 for n, _ in sheet.calls if n in _WRITERS))
    spelled = "\n".join(sheet.built + [a for _, args in sheet.calls for a in args])
    contentscan._scan_text(spelled + "\n" + "\n".join(formulas.values()), st, 0)  # noqa: SLF001
    if len(re.findall(r"(?i)\bchar\s*\(", " ".join(formulas.values()))) >= 15:
        st.add("macro_obfuscated_code")
    out: dict[str, Any] = contentscan.result(data, "xlm", st)
    return out
