"""A bounded evaluator for the text-building code of a VBA macro. Standard library only; runs
INSIDE the sandbox on hostile input.

Malware hides what it does by building its commands at run time ("power" & "shell", Chr() chains,
a hex decoder function, an XOR loop over an array). A keyword search cannot see through a decoder
the author wrote, but the decoder is ordinary arithmetic and string handling, so this module runs
it: the macro is parsed into a small tree and the pure part (string, number and array handling,
the macro's own Subs and Functions) is evaluated. Everything else is NOT performed: Shell,
CreateObject, file, registry, network and every unknown call return an opaque value, and the
strings handed to them are only recorded. So nothing is ever executed, and nothing real is
touched.

What comes out is the list of strings the macro would have built (the ones that are not already
written out in its source). The caller searches them like any script. Every loop, call depth,
array, string and the wall clock is bounded (limits.py); hitting a bound ends that entry point and
keeps what was recovered so far. A construct that is not understood becomes an opaque value, never
an error.
"""

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from limits import (
    MAX_EVAL_ARRAY,
    MAX_EVAL_DEPTH,
    MAX_EVAL_ROOTS,
    MAX_EVAL_SECONDS,
    MAX_EVAL_STEPS,
    MAX_EVAL_STRING,
    MAX_EVAL_STRINGS,
)


class _Opaque:
    """A value that is not known (the result of something that is never performed)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<opaque>"


OPAQUE: Any = _Opaque()


class _Stop(BaseException):
    """A bound was reached: end this entry point."""


class _Exit(BaseException):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


AUTOEXEC = frozenset(
    {
        "autoopen", "auto_open", "autoexec", "auto_exec", "autoclose", "auto_close", "autonew",
        "auto_new", "document_open", "document_new", "document_close", "workbook_open",
        "workbook_activate", "auto_activate", "autoactivate", "workbook_beforeclose",
    }
)  # fmt: skip

# ---- reading the text --------------------------------------------------------------------------
_TOKEN = re.compile(
    r"""(?:(?P<ws>[ \t]+)
    |(?P<str>"(?:[^"]|"")*")
    |(?P<num>&[Hh][0-9A-Fa-f]+&?|&[Oo][0-7]+&?|\d+\.\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?
        |\d+(?:[eE][+-]?\d+)?[%#!@]?)
    |(?P<id>[A-Za-z_]\w*[$%#!@]?)
    |(?P<op><>|<=|>=|:=|[-+*/\\^&=<>(),.:#]))""",
    re.VERBOSE,
)
_MODS = frozenset({"public", "private", "friend", "static", "global"})
_KEYWORDS = frozenset(
    {
        "if", "elseif", "else", "for", "next", "while", "wend", "do", "loop", "select", "case",
        "with", "sub", "function", "property", "dim", "redim", "const", "set", "let", "call",
        "exit", "end", "on", "option", "attribute", "declare", "goto", "resume", "stop", "type",
        "enum", "static",
    }
)  # fmt: skip
Tok = tuple[str, str]


def _strip_comment(line: str) -> str:
    in_str = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_str = not in_str
        elif ch == "'" and not in_str:
            return line[:i]
    return line


def logical_lines(text: str) -> list[str]:
    """Source lines with comments removed and line continuations (" _") joined."""
    out: list[str] = []
    cur = ""
    for raw in re.split(r"\r\n|\r|\n", text):
        line = _strip_comment(raw).rstrip()
        if line.endswith(" _") or line == "_":
            cur += line[:-1]
            continue
        line = cur + line
        cur = ""
        if re.match(r"(?i)\s*rem(\s|$)", line):
            continue
        if line.strip():
            out.append(line)
    if cur.strip():
        out.append(cur)
    return out


def _tokenize(line: str) -> list[Tok]:
    out: list[Tok] = []
    pos, n = 0, len(line)
    while pos < n:
        m = _TOKEN.match(line, pos)
        if not m or m.end() == pos:
            raise ValueError("bad token")
        pos = m.end()
        kind = m.lastgroup or ""
        if kind != "ws":
            out.append((kind, m.group(kind)))
    return out


def _split_statements(toks: list[Tok]) -> list[list[Tok]]:
    out: list[list[Tok]] = [[]]
    for t in toks:
        if t == ("op", ":"):
            out.append([])
        else:
            out[-1].append(t)
    return [s for s in out if s]


def _number(text: str) -> int | float:
    t = text.rstrip("%#!@&")
    if t[:2].lower() == "&h":
        return int(t[2:], 16)
    if t[:2].lower() == "&o":
        return int(t[2:], 8)
    return float(t) if re.search(r"[.eE]", t) else int(t)


# ---- expressions -------------------------------------------------------------------------------
_PREC = {
    "=": 7, "<>": 7, "<": 7, ">": 7, "<=": 7, ">=": 7, "&": 8, "+": 9, "-": 9, "\\": 11,
    "*": 12, "/": 12, "^": 14,
}  # fmt: skip
_KWP = {"imp": 1, "eqv": 2, "xor": 3, "or": 4, "and": 5, "is": 7, "like": 7, "mod": 10}
Node = tuple[Any, ...]


def _bare(word: str) -> str:
    return word.lower().rstrip("$%#!@")


class _P:
    """A tiny precedence-climbing parser over one statement's tokens."""

    def __init__(self, toks: list[Tok]) -> None:
        self.t, self.i = toks, 0

    def peek(self) -> Tok:
        return self.t[self.i] if self.i < len(self.t) else ("", "")

    def next(self) -> Tok:
        tok = self.peek()
        self.i += 1
        return tok

    def isop(self, v: str) -> bool:
        return self.peek() == ("op", v)

    def iskw(self, v: str) -> bool:
        k, x = self.peek()
        return k == "id" and x.lower() == v

    def expect(self, v: str) -> None:
        if not self.isop(v):
            raise ValueError("expected " + v)
        self.i += 1

    def done(self) -> bool:
        return self.i >= len(self.t)

    def expr(self, minp: int = 0) -> Node:
        if self.iskw("not"):
            self.i += 1
            left: Node = ("un", "not", self.expr(7))
        else:
            left = self.unary()
        while True:
            k, x = self.peek()
            if k == "op" and x in _PREC:
                p, op = _PREC[x], x
            elif k == "id" and x.lower() in _KWP:
                p, op = _KWP[x.lower()], x.lower()
            else:
                return left
            if p < minp:
                return left
            self.i += 1
            left = ("bin", op, left, self.expr(p + 1))

    def unary(self) -> Node:
        if self.isop("-"):
            self.i += 1
            return ("un", "-", self.expr(13))
        if self.isop("+"):
            self.i += 1
            return self.expr(13)
        return self.postfix(self.primary())

    def primary(self) -> Node:
        k, x = self.next()
        if k == "num":
            return ("lit", _number(x))
        if k == "str":
            return ("lit", x[1:-1].replace('""', '"'))
        if k == "id":
            word = _bare(x)
            if word == "new":
                while self.peek()[0] == "id" or self.isop("."):
                    self.i += 1
                return ("opaque",)
            return ("name", word)
        if (k, x) == ("op", "("):
            e = self.expr()
            self.expect(")")
            return e
        if (k, x) == ("op", "."):
            self.next()
            return ("opaque",)
        if (k, x) == ("op", "#"):  # a file number: Print #1, text
            return self.unary()
        raise ValueError("unexpected token")

    def postfix(self, e: Node) -> Node:
        while True:
            if self.isop("("):
                self.i += 1
                e = ("call", e, self.args())
            elif self.isop("."):
                self.i += 1
                k, x = self.next()
                if k != "id":
                    raise ValueError("member name expected")
                e = ("member", e, _bare(x))
            else:
                return e

    def args(self) -> list[Node]:
        out: list[Node] = []
        while True:
            if self.isop(")"):
                self.i += 1
                return out
            if self.isop(","):
                out.append(("lit", None))
                self.i += 1
                continue
            if self.peek()[0] == "id" and self.t[self.i + 1 : self.i + 2] == [("op", ":=")]:
                self.i += 2
            out.append(self.expr())
            if self.isop(","):
                self.i += 1
                if self.isop(")"):
                    out.append(("lit", None))
            elif not self.isop(")"):
                raise ValueError("bad argument list")


# ---- statements --------------------------------------------------------------------------------
@dataclass
class _Proc:
    name: str
    params: list[str]
    is_function: bool
    body: list[Node] = field(default_factory=list)
    ids: set[str] = field(default_factory=set)  # every word used inside (for the call graph)
    text: str = ""  # the cleaned source lines of this procedure


def _lead(toks: list[Tok]) -> tuple[str, list[Tok]]:
    """The statement's leading keyword (modifiers dropped) and the tokens after it."""
    rest = toks
    while rest and rest[0][0] == "id" and rest[0][1].lower() in _MODS:
        rest = rest[1:]
    if not rest or rest[0][0] != "id":
        return "", rest
    word = rest[0][1].lower()
    if word in ("end", "exit") and len(rest) > 1 and rest[1][0] == "id":
        return word + " " + rest[1][1].lower(), rest[2:]
    return word, rest[1:]


class Program:
    def __init__(self, text: str) -> None:
        self.procs: dict[str, _Proc] = {}
        self.init: list[Node] = []
        self.literals: set[str] = set()
        self.assigned: set[str] = set()  # names the macro itself assigns: Empty until then
        self.lines: list[tuple[str, list[Tok], str]] = []
        for raw in logical_lines(text):
            try:
                statements = _split_statements(_tokenize(raw))
            except ValueError:
                continue
            for s in statements:
                for kind, val in s:
                    if kind == "str":
                        self.literals.add(val[1:-1].replace('""', '"'))
                kw, rest = _lead(s)
                self.lines.append((kw, rest if kw else s, raw))
                if kw and rest and rest[0] == ("op", "=") and kw not in _KEYWORDS:
                    self.assigned.add(kw.rstrip("$%#!@"))
                elif kw in ("dim", "static", "const", "redim", "for", "set", "let"):
                    self.assigned |= {_bare(v) for k, v in rest if k == "id"}
        self._top()

    # -- structure
    def _top(self) -> None:
        i, n = 0, len(self.lines)
        while i < n:
            kw, toks, raw = self.lines[i]
            i += 1
            if kw in ("sub", "function", "property"):
                i = self._proc(kw, toks, i)
            elif kw in ("type", "enum"):
                while i < n and self.lines[i][0] not in ("end type", "end enum"):
                    i += 1
                i += 1
            else:
                node = self._simple_safe(kw, toks)
                if node is not None:
                    self.init.append(node)

    def _proc(self, kw: str, toks: list[Tok], i: int) -> int:
        try:
            idx = 0
            if kw == "property":
                idx = 1  # Get / Let / Set
            name = _bare(toks[idx][1])
            params: list[str] = []
            depth, expect_name = 0, True
            for kind, val in toks[idx + 1 :]:
                if (kind, val) == ("op", "("):
                    depth += 1
                elif (kind, val) == ("op", ")"):
                    depth -= 1
                    if depth <= 0:
                        break
                elif depth == 1 and (kind, val) == ("op", ","):
                    expect_name = True
                elif (
                    depth == 1
                    and kind == "id"
                    and expect_name
                    and val.lower() not in ("byval", "byref", "optional", "paramarray")
                ):
                    params.append(_bare(val))
                    expect_name = False
        except (IndexError, ValueError):
            params, name = [], ""
        start = i
        body, i = self._block(i, {"end sub", "end function", "end property"})
        if name:
            proc = _Proc(name, params, kw != "sub", body)
            lines = self.lines[start:i]
            proc.text = "\n".join(raw for _, _, raw in lines)
            proc.ids = {_bare(v) for _, t, _ in lines for k, v in t if k == "id"}
            proc.ids |= {_bare(kw) for kw, _, _ in lines if kw}  # a call that starts a statement
            if name not in self.procs or kw == "function" or not self.procs[name].is_function:
                self.procs[name] = proc
        return i + 1

    def _block(self, i: int, stops: set[str]) -> tuple[list[Node], int]:
        out: list[Node] = []
        n = len(self.lines)
        while i < n:
            kw, toks, _raw = self.lines[i]
            if kw in stops:
                return out, i
            i += 1
            node: Node | None
            try:
                if kw == "if":
                    node, i = self._if(toks, i)
                elif kw == "for":
                    node, i = self._for(toks, i)
                elif kw == "while":
                    cond = _P(toks).expr()
                    body, i = self._block(i, {"wend"})
                    i += 1
                    node = ("while", cond, body)
                elif kw == "do":
                    node, i = self._do(toks, i)
                elif kw == "select":
                    node, i = self._select(toks, i)
                elif kw == "with":
                    body, i = self._block(i, {"end with"})
                    i += 1
                    node = ("block", body)
                else:
                    node = self._simple_safe(kw, toks)
            except (ValueError, IndexError):
                node = None
            if node is not None:
                out.append(node)
        return out, i

    def _if(self, toks: list[Tok], i: int) -> tuple[Node, int]:
        words = [t[1].lower() if t[0] == "id" else "" for t in toks]
        depth, then = 0, -1
        for j, t in enumerate(toks):
            depth += t == ("op", "(")
            depth -= t == ("op", ")")
            if depth == 0 and words[j] == "then":
                then = j
                break
        if then < 0:
            raise ValueError("no Then")
        cond = _P(toks[:then]).expr()
        after = toks[then + 1 :]
        if after:  # single-line If
            after_words = [t[1].lower() if t[0] == "id" else "" for t in after]
            else_at = after_words.index("else") if "else" in after_words else -1
            first = after if else_at < 0 else after[:else_at]
            other = [] if else_at < 0 else after[else_at + 1 :]
            then_nodes = [x for x in (self._stmt(first),) if x is not None]
            else_nodes = [x for x in (self._stmt(other),) if x is not None] if other else []
            return ("if", [(cond, then_nodes)], else_nodes), i
        branches: list[tuple[Node, list[Node]]] = []
        else_body: list[Node] = []
        body, i = self._block(i, {"elseif", "else", "end if"})
        branches.append((cond, body))
        while i < len(self.lines):
            kw, rest, _raw = self.lines[i]
            i += 1
            if kw == "elseif":
                c = _P(rest[: _then_index(rest)]).expr()
                body, i = self._block(i, {"elseif", "else", "end if"})
                branches.append((c, body))
            elif kw == "else":
                else_body, i = self._block(i, {"end if"})
            else:  # end if
                break
        return ("if", branches, else_body), i

    def _for(self, toks: list[Tok], i: int) -> tuple[Node, int]:
        p = _P(toks)
        if p.iskw("each"):
            p.i += 1
            var = _bare(p.next()[1])
            if not p.iskw("in"):
                raise ValueError("For Each without In")
            p.i += 1
            seq = p.expr()
            body, i = self._block(i, {"next"})
            return ("foreach", var, seq, body), i + 1
        var = _bare(p.next()[1])
        p.expect("=")
        start = p.expr()
        if not p.iskw("to"):
            raise ValueError("For without To")
        p.i += 1
        stop = p.expr()
        step: Node = ("lit", 1)
        if p.iskw("step"):
            p.i += 1
            step = p.expr()
        body, i = self._block(i, {"next"})
        return ("for", var, start, stop, step, body), i + 1

    def _do(self, toks: list[Tok], i: int) -> tuple[Node, int]:
        pre = _cond_clause(toks)
        body, i = self._block(i, {"loop"})
        post = _cond_clause(self.lines[i][1]) if i < len(self.lines) else None
        return ("do", pre, post, body), i + 1

    def _select(self, toks: list[Tok], i: int) -> tuple[Node, int]:
        p = _P(toks)
        if p.iskw("case"):
            p.i += 1
        subject = p.expr()
        cases: list[tuple[list[Node] | None, list[Node]]] = []
        while i < len(self.lines):
            kw, rest, _raw = self.lines[i]
            i += 1
            if kw == "end select":
                break
            if kw != "case":
                continue
            conds: list[Node] | None
            if rest and rest[0][1].lower() == "else":
                conds = None
            else:
                conds = [_case_cond(part) for part in _split_commas(rest)]
            body, i = self._block(i, {"case", "end select"})
            cases.append((conds, body))
        return ("select", subject, cases), i

    # -- single statements
    def _simple_safe(self, kw: str, toks: list[Tok]) -> Node | None:
        try:
            return self._simple(kw, toks)
        except (ValueError, IndexError):
            return None

    def _stmt(self, toks: list[Tok]) -> Node | None:
        kw, rest = _lead(toks)
        return self._simple_safe(kw, rest if kw else toks)

    def _simple(self, kw: str, toks: list[Tok]) -> Node | None:
        if kw in ("dim", "static"):
            return ("dim", _declared(toks))
        if kw == "redim":
            p = _P(toks)
            if p.iskw("preserve"):
                p.i += 1
            return ("redim", [(n, d) for n, d in _declared(toks[p.i :])])
        if kw == "const":
            out: list[tuple[str, Node]] = []
            for part in _split_commas(toks):
                q = _P(part)
                name = _bare(q.next()[1])
                while not q.isop("=") and not q.done():
                    q.i += 1
                q.expect("=")
                out.append((name, q.expr()))
            return ("const", out)
        if kw in ("exit for", "exit do", "exit sub", "exit function", "exit property"):
            return ("exit", kw.split()[1])
        if kw in ("option", "attribute", "declare", "on", "goto", "resume", "stop", "end"):
            return None
        if kw not in ("set", "let", "call") and kw:
            toks = [("id", kw), *toks]  # the leading word was a name, not a keyword
        if not toks:
            return None
        p = _P(toks)
        target = p.postfix(p.primary())
        if p.isop("="):
            p.i += 1
            return ("let", target, p.expr())
        args: list[Node] = []
        while not p.done():
            args.append(p.expr())
            if p.isop(","):
                p.i += 1
            elif not p.done():
                raise ValueError("bad call")
        if target[0] == "call" and not args:
            return ("call", target[1], target[2])
        return ("call", target, args)


def _then_index(toks: list[Tok]) -> int:
    for j, t in enumerate(toks):
        if t[0] == "id" and t[1].lower() == "then":
            return j
    return len(toks)


def _cond_clause(toks: list[Tok]) -> tuple[str, Node] | None:
    if not toks or toks[0][0] != "id" or toks[0][1].lower() not in ("while", "until"):
        return None
    return toks[0][1].lower(), _P(toks[1:]).expr()


def _split_commas(toks: list[Tok]) -> list[list[Tok]]:
    parts: list[list[Tok]] = [[]]
    depth = 0
    for t in toks:
        depth += t == ("op", "(")
        depth -= t == ("op", ")")
        if depth == 0 and t == ("op", ","):
            parts.append([])
        else:
            parts[-1].append(t)
    return [p for p in parts if p]


def _case_cond(toks: list[Tok]) -> Node:
    p = _P(toks)
    if p.iskw("is"):
        p.i += 1
        op = p.next()[1]
        return ("is", op, p.expr())
    first = p.expr()
    if p.iskw("to"):
        p.i += 1
        return ("range", first, p.expr())
    return first


def _declared(toks: list[Tok]) -> list[tuple[str, list[Node] | None]]:
    out: list[tuple[str, list[Node] | None]] = []
    for part in _split_commas(toks):
        q = _P(part)
        while q.peek()[0] == "id" and q.peek()[1].lower() in ("withevents", "preserve"):
            q.i += 1
        name = _bare(q.next()[1])
        dims: list[Node] | None = None
        if q.isop("("):
            q.i += 1
            dims = q.args()
        out.append((name, dims))
    return out


# ---- running it --------------------------------------------------------------------------------
_KEEP = 16 * 1024  # characters kept of one recovered string


def _clip(s: str) -> str:
    return s if len(s) <= MAX_EVAL_STRING else s[:MAX_EVAL_STRING]


def _text(v: Any) -> Any:
    if v is OPAQUE or isinstance(v, list):
        return OPAQUE
    if v is None:
        return ""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, float):
        return str(int(v)) if v == int(v) and abs(v) < 1e15 else repr(v)
    return str(v)


_NUM_PREFIX = re.compile(
    r"^\s*(&[Hh][0-9A-Fa-f]+|&[Oo][0-7]+|[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)"
)


def _val(s: str) -> int | float:
    m = _NUM_PREFIX.match(s)
    if not m:
        return 0
    t = m.group(1)
    if t[0] == "&":
        return _number(t)
    return float(t) if re.search(r"[.eE]", t) else int(t)


def _numeric(v: Any) -> Any:
    if v is OPAQUE or isinstance(v, list):
        return OPAQUE
    if v is None:
        return 0
    if isinstance(v, bool):
        return -1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        m = _NUM_PREFIX.fullmatch(v.strip()) if v.strip() else None
        if not m:
            raise ValueError("type mismatch")
        return _val(v)
    raise ValueError("type mismatch")


def _int(v: Any) -> int:
    n = _numeric(v)
    if n is OPAQUE:
        raise ValueError("opaque")
    return int(round(n)) if isinstance(n, float) else int(n)


def _truth(v: Any) -> bool | None:
    if v is OPAQUE or isinstance(v, list):
        return None
    if isinstance(v, bool):
        return v
    try:
        return bool(_numeric(v) != 0)
    except ValueError:
        return None


def _chr(n: Any, wide: bool = False) -> str:
    code = _int(n)
    if code < 0:
        code += 65536
    if code > (0xFFFF if wide else 255):
        raise ValueError("bad code")
    return chr(code)


def _mid(s: Any, start: Any, length: Any = None) -> str:
    t, a = _text(s), _int(start)
    if a < 1:
        raise ValueError("bad start")
    return str(t[a - 1 :] if length is None else t[a - 1 : a - 1 + max(_int(length), 0)])


def _instr(*a: Any) -> int:
    start = 1
    if len(a) >= 3 and isinstance(a[0], (int, float)) and not isinstance(a[0], bool):
        start, a = _int(a[0]), a[1:]
    hay, needle = _text(a[0]), _text(a[1])
    return int(hay.find(needle, start - 1)) + 1


def _split(s: Any, d: Any = " ", *_: Any) -> list[Any]:
    delim = _text(d)
    return list(_text(s).split(delim)) if delim else [_text(s)]


def _replace(s: Any, a: Any, b: Any, *_: Any) -> str:
    old = _text(a)
    return str(_text(s).replace(old, _text(b)) if old else _text(s))


def _string(n: Any, c: Any) -> str:
    ch = _chr(c) if isinstance(c, (int, float)) else _text(c)[:1]
    count: int = min(max(_int(n), 0), 1 << 18)
    return str(ch) * count


_BUILTINS: dict[str, Callable[..., Any]] = {
    "len": lambda s: len(_text(s)),
    "mid": _mid,
    "left": lambda s, n: _text(s)[: max(_int(n), 0)],
    "right": lambda s, n: _text(s)[len(_text(s)) - max(_int(n), 0) :] if _int(n) > 0 else "",
    "chr": _chr, "chrb": _chr, "chrw": lambda n: _chr(n, True),
    "asc": lambda s: ord(_text(s)[0]), "ascw": lambda s: ord(_text(s)[0]),
    "ascb": lambda s: ord(_text(s)[0]),
    "lcase": lambda s: _text(s).lower(), "ucase": lambda s: _text(s).upper(),
    "trim": lambda s: _text(s).strip(" "), "ltrim": lambda s: _text(s).lstrip(" "),
    "rtrim": lambda s: _text(s).rstrip(" "),
    "replace": _replace, "strreverse": lambda s: _text(s)[::-1],
    "space": lambda n: " " * min(max(_int(n), 0), MAX_EVAL_STRING),
    "string": _string, "instr": _instr,
    "split": _split, "join": lambda a, d=" ": _text(d).join(_text(x) for x in a),
    "ubound": lambda a, *_: len(a) - 1, "lbound": lambda a, *_: 0,
    "hex": lambda n: format(_int(n) & 0xFFFFFFFF, "X") if _int(n) < 0 else format(_int(n), "X"),
    "oct": lambda n: format(_int(n), "o"),
    "cint": _int, "clng": _int, "cbyte": lambda n: _int(n) & 0xFF, "cstr": _text,
    "cdbl": lambda v: float(_numeric(v)), "csng": lambda v: float(_numeric(v)),
    "val": lambda s: _val(_text(s)), "abs": lambda v: abs(_numeric(v)),
    "int": lambda v: math.floor(_numeric(v)), "fix": lambda v: math.trunc(_numeric(v)),
    "sgn": lambda v: (_numeric(v) > 0) - (_numeric(v) < 0),
    "round": lambda v, d=0: round(_numeric(v), _int(d)),
    "strconv": lambda s, *_: _text(s),
    "str": lambda v: (" " if _numeric(v) >= 0 else "") + _text(v),
    "isnumeric": lambda v: isinstance(v, (int, float))
    or (isinstance(v, str) and bool(_NUM_PREFIX.fullmatch(v.strip() or "x"))),
    "isempty": lambda v: v is None, "isarray": lambda v: isinstance(v, list),
    "array": lambda *a: list(a),
}  # fmt: skip
_CONSTANTS: dict[str, Any] = {
    "true": True, "false": False, "empty": None, "null": None, "nothing": None,
    "vbcrlf": "\r\n", "vbcr": "\r", "vblf": "\n", "vbtab": "\t", "vbnullstring": "",
    "vbnullchar": "\x00", "vbnewline": "\r\n", "vbback": "\b", "vbformfeed": "\f",
    "vbverticaltab": "\v", "vbunicode": 64, "vbfromunicode": 128,
}  # fmt: skip


@dataclass
class EvalResult:
    strings: list[str]
    truncated: bool  # a bound stopped some entry point
    steps: int
    entries: int
    by_root: dict[str, list[str]] = field(default_factory=dict)  # strings built under each entry


class _Run:
    def __init__(self, prog: Program) -> None:
        self.prog = prog
        self.g: dict[str, Any] = {}
        self.out: list[str] = []
        self.seen: set[str] = set()
        self.steps = 0
        self.limit = MAX_EVAL_STEPS
        self.depth = 0
        self.truncated = False
        self.deadline = time.monotonic() + MAX_EVAL_SECONDS

    # -- bookkeeping
    def step(self) -> None:
        self.steps += 1
        if self.steps > self.limit:
            raise _Stop
        if self.steps & 255 == 0 and time.monotonic() > self.deadline:
            raise _Stop

    def capture(self, v: Any) -> None:
        """Remember a string the macro built (not one it already contains verbatim)."""
        if (
            isinstance(v, str)
            and len(v) >= 4
            and v not in self.prog.literals
            and v not in self.seen
            and len(self.out) < MAX_EVAL_STRINGS
        ):
            self.seen.add(v)
            self.out.append(v[:_KEEP])

    def capture_final(self, frame: dict[str, Any]) -> None:
        """The final value of every variable (not every step on the way to it)."""
        for v in frame.values():
            self.capture(v)

    # -- values
    def lookup(self, name: str, frame: dict[str, Any]) -> Any:
        if name in frame:
            return frame[name]
        if name in self.g:
            return self.g[name]
        if name in _CONSTANTS:
            return _CONSTANTS[name]
        if name in self.prog.procs and not self.prog.procs[name].params:
            return self.invoke(name, [])
        return None if name in self.prog.assigned else OPAQUE

    def assign(self, name: str, value: Any, frame: dict[str, Any]) -> None:
        if name in frame or name not in self.g:
            frame[name] = value
        else:
            self.g[name] = value

    def ev(self, node: Node, frame: dict[str, Any]) -> Any:
        self.step()
        kind = node[0]
        try:
            if kind == "lit":
                return node[1]
            if kind == "name":
                return self.lookup(node[1], frame)
            if kind == "bin":
                return self.binary(node[1], self.ev(node[2], frame), self.ev(node[3], frame))
            if kind == "un":
                v = self.ev(node[2], frame)
                if v is OPAQUE:
                    return OPAQUE
                if node[1] == "not":
                    return (not v) if isinstance(v, bool) else ~_int(v)
                n = _numeric(v)
                return OPAQUE if n is OPAQUE else -n
            if kind == "call":
                return self.call(node[1], node[2], frame)
            if kind == "member":
                self.ev(node[1], frame)
                return OPAQUE
        except (ValueError, TypeError, ZeroDivisionError, OverflowError, IndexError, KeyError):
            return OPAQUE
        return OPAQUE

    def binary(self, op: str, a: Any, b: Any) -> Any:
        if op == "&":
            x, y = _text(a), _text(b)
            return OPAQUE if x is OPAQUE or y is OPAQUE else _clip(x + y)
        if a is OPAQUE or b is OPAQUE:
            return OPAQUE
        if op == "+":
            if isinstance(a, str) and isinstance(b, str):
                return _clip(a + b)
            return _numeric(a) + _numeric(b)
        if op in ("=", "<>", "<", ">", "<=", ">=", "is", "like"):
            lhs: Any
            rhs: Any
            if isinstance(a, str) and isinstance(b, str):
                lhs, rhs = a, b
            else:
                lhs, rhs = _numeric(a), _numeric(b)
            return {"=": lhs == rhs, "is": lhs == rhs, "<>": lhs != rhs, "<": lhs < rhs,
                    ">": lhs > rhs, "<=": lhs <= rhs, ">=": lhs >= rhs,
                    "like": lhs == rhs}[op]  # fmt: skip
        if op in ("and", "or", "xor", "eqv", "imp"):
            if isinstance(a, bool) and isinstance(b, bool):
                return {"and": a and b, "or": a or b, "xor": a != b, "eqv": a == b,
                        "imp": (not a) or b}[op]  # fmt: skip
            i, j = _int(a), _int(b)
            return {"and": i & j, "or": i | j, "xor": i ^ j, "eqv": ~(i ^ j), "imp": ~i | j}[op]
        x2, y2 = _numeric(a), _numeric(b)
        if op == "-":
            return x2 - y2
        if op == "*":
            return x2 * y2
        if op == "/":
            return x2 / y2
        if op == "\\":
            return int(_int(x2) / _int(y2))
        if op == "mod":
            return int(math.fmod(_int(x2), _int(y2)))
        if op == "^":
            return x2**y2 if abs(y2) < 64 else OPAQUE
        return OPAQUE

    def call(self, target: Node, arg_nodes: list[Node], frame: dict[str, Any]) -> Any:
        if target[0] == "name":
            name = target[1]
            here = frame.get(name, self.g.get(name))
            if isinstance(here, list):
                idx = [self.ev(a, frame) for a in arg_nodes]
                if len(idx) == 1 and idx[0] is not OPAQUE and 0 <= _int(idx[0]) < len(here):
                    return here[_int(idx[0])]
                return OPAQUE
            vals = [self.ev(a, frame) for a in arg_nodes]
            if name in self.prog.procs:
                return self.invoke(name, vals)
            if name in _BUILTINS:
                if name != "array" and any(v is OPAQUE for v in vals):
                    return OPAQUE
                result = _BUILTINS[name](*vals)
                return result if name != "array" or len(result) <= MAX_EVAL_ARRAY else OPAQUE
            for (
                v
            ) in vals:  # an unknown call (Shell, CreateObject, ...): never performed, only noted
                self.capture(v)
            return OPAQUE
        for a in arg_nodes:
            self.capture(self.ev(a, frame))
        self.ev(target, frame)
        return OPAQUE

    def invoke(self, name: str, args: list[Any]) -> Any:
        proc = self.prog.procs[name]
        if self.depth >= MAX_EVAL_DEPTH:
            return OPAQUE
        frame: dict[str, Any] = {
            p: (args[i] if i < len(args) else None) for i, p in enumerate(proc.params)
        }
        if proc.is_function:
            frame[name] = None
        self.depth += 1
        try:
            self.exec_block(proc.body, frame)
        except _Exit as e:
            if e.kind not in ("sub", "function", "property"):
                raise
        finally:
            self.depth -= 1
            self.capture_final(frame)
        return frame.get(name) if proc.is_function else None

    # -- statements
    def exec_block(self, block: list[Node], frame: dict[str, Any]) -> None:
        for node in block:
            self.step()
            try:
                self.exec_node(node, frame)
            except (ValueError, TypeError, ZeroDivisionError, OverflowError, IndexError, KeyError):
                continue  # what VBA would call a run-time error: this statement does nothing

    def loop_body(self, body: list[Node], frame: dict[str, Any], kind: str) -> bool:
        """Run a loop body once; False when it ended with Exit For / Exit Do."""
        try:
            self.exec_block(body, frame)
        except _Exit as e:
            if e.kind != kind:
                raise
            return False
        return True

    def exec_node(self, node: Node, frame: dict[str, Any]) -> None:
        kind = node[0]
        if kind == "let":
            value = self.ev(node[2], frame)
            target = node[1]
            if target[0] == "name":
                self.assign(target[1], value, frame)
            elif target[0] == "call" and target[1][0] == "name" and len(target[2]) == 1:
                arr = frame.get(target[1][1], self.g.get(target[1][1]))
                idx = self.ev(target[2][0], frame)
                if isinstance(arr, list) and idx is not OPAQUE and 0 <= _int(idx) < len(arr):
                    arr[_int(idx)] = value
                self.capture(value)
            else:
                self.capture(value)
        elif kind == "call":
            self.call(node[1], node[2], frame)
        elif kind == "dim":
            for name, dims in node[1]:
                if dims:
                    size = _int(self.ev(dims[-1], frame))
                    frame[name] = [None] * (size + 1) if 0 <= size < MAX_EVAL_ARRAY else OPAQUE
                else:
                    frame.setdefault(name, None)
        elif kind == "redim":
            for name, dims in node[1]:
                if dims:
                    size = _int(self.ev(dims[-1], frame))
                    old = frame.get(name, self.g.get(name))
                    new = [None] * (size + 1) if 0 <= size < MAX_EVAL_ARRAY else OPAQUE
                    if isinstance(old, list) and isinstance(new, list):
                        new[: len(old)] = old[: len(new)]
                    self.assign(name, new, frame)
        elif kind == "const":
            for name, e in node[1]:
                frame[name] = self.ev(e, frame)
        elif kind == "if":
            self.exec_if(node, frame)
        elif kind == "for":
            self.exec_for(node, frame)
        elif kind == "foreach":
            seq = self.ev(node[2], frame)
            for item in seq if isinstance(seq, list) else [OPAQUE]:
                self.step()
                self.assign(node[1], item, frame)
                if not self.loop_body(node[3], frame, "for"):
                    break
        elif kind == "while":
            while True:
                self.step()
                t = _truth(self.ev(node[1], frame))
                if t is False or not self.loop_body(node[2], frame, "do"):
                    break
                if t is None:
                    break
        elif kind == "do":
            self.exec_do(node, frame)
        elif kind == "select":
            self.exec_select(node, frame)
        elif kind == "exit":
            raise _Exit(node[1])
        elif kind == "block":
            self.exec_block(node[1], frame)

    def exec_if(self, node: Node, frame: dict[str, Any]) -> None:
        for cond, body in node[1]:
            t = _truth(self.ev(cond, frame))
            if t is True:
                self.exec_block(body, frame)
                return
            if t is None:  # unknown: look at both ways, so a guarded command is still seen
                self.exec_block(body, frame)
        if node[2]:
            self.exec_block(node[2], frame)

    def exec_for(self, node: Node, frame: dict[str, Any]) -> None:
        start, stop, step = (self.ev(node[i], frame) for i in (2, 3, 4))
        var, body = node[1], node[5]
        try:
            s, e, st = _numeric(start), _numeric(stop), _numeric(step)
        except ValueError:
            s = e = st = OPAQUE
        if OPAQUE in (s, e, st) or st == 0:
            self.assign(var, OPAQUE if s is OPAQUE else s, frame)
            self.loop_body(body, frame, "for")
            return
        i = s
        while (i <= e) if st > 0 else (i >= e):
            self.step()
            self.assign(var, i, frame)
            if not self.loop_body(body, frame, "for"):
                return
            i += st

    def exec_do(self, node: Node, frame: dict[str, Any]) -> None:
        pre, post, body = node[1], node[2], node[3]
        while True:
            self.step()
            if pre:
                t = _truth(self.ev(pre[1], frame))
                if t is None:
                    self.loop_body(body, frame, "do")
                    return
                if t != (pre[0] == "while"):
                    return
            if not self.loop_body(body, frame, "do"):
                return
            if post:
                t = _truth(self.ev(post[1], frame))
                if t is None or t != (post[0] == "while"):
                    return

    def exec_select(self, node: Node, frame: dict[str, Any]) -> None:
        subject = self.ev(node[1], frame)
        for conds, body in node[2]:
            if conds is None:
                self.exec_block(body, frame)
                return
            hit: bool | None = False
            for c in conds:
                m = self.case_match(subject, c, frame)
                if m is True:
                    hit = True
                    break
                if m is None:
                    hit = None
            if hit is True:
                self.exec_block(body, frame)
                return
            if hit is None:
                self.exec_block(body, frame)

    def case_match(self, subject: Any, cond: Node, frame: dict[str, Any]) -> bool | None:
        if subject is OPAQUE:
            return None
        if cond[0] == "range":
            lo, hi = self.ev(cond[1], frame), self.ev(cond[2], frame)
            return None if OPAQUE in (lo, hi) else bool(lo <= subject <= hi)
        if cond[0] == "is":
            r = self.binary(cond[1], subject, self.ev(cond[2], frame))
            return None if r is OPAQUE else bool(r)
        r = self.binary("=", subject, self.ev(cond, frame))
        return None if r is OPAQUE else bool(r)


def _roots(prog: Program) -> list[str]:
    called: set[str] = set()
    for name, p in prog.procs.items():
        called |= {w for w in p.ids if w in prog.procs and w != name}
    auto = [n for n in prog.procs if n in AUTOEXEC]
    rest = [n for n in prog.procs if n not in called and n not in AUTOEXEC]
    return (auto + rest)[:MAX_EVAL_ROOTS]


def run(prog: Program) -> EvalResult:
    state = _Run(prog)
    roots = _roots(prog)
    per_entry = max(5_000, MAX_EVAL_STEPS // max(1, min(len(roots) + 1, 10)))
    total = 0
    try:
        state.limit = per_entry
        for node in prog.init:  # module-level Dim / Const
            state.exec_node(node, state.g)
    except (_Stop, _Exit):
        state.truncated = True
    total += state.steps
    by_root: dict[str, list[str]] = {}
    for name in roots:
        state.steps, state.limit, state.depth = 0, per_entry, 0
        if time.monotonic() > state.deadline:
            state.truncated = True
            break
        mark = len(state.out)
        try:
            state.invoke(name, [OPAQUE] * len(prog.procs[name].params))
        except _Stop:
            state.truncated = True
        except _Exit:
            pass
        by_root[name] = state.out[mark:]
        total += state.steps
    state.capture_final(state.g)
    return EvalResult(state.out, state.truncated, total, len(roots), by_root)


def evaluate(text: str) -> EvalResult:
    """The strings a macro's own code builds, without running anything real. Never raises: whatever
    goes wrong, the answer is "nothing recovered" and the scan carries on."""
    try:
        return run(Program(text))
    except Exception:  # noqa: BLE001  (hostile input; a bug here must never fail the file's scan)
        return EvalResult([], True, 0, 0)
