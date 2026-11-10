"""What the SHAPE of a macro gives away, for macros no list or keyword has ever seen. Standard
library only; runs INSIDE the sandbox on hostile input.

A keyword search finds known tricks. An unknown macro still has to start by itself, hide what it
does, reach something that runs programs, load or drop a payload. This module reads the macro as a
program and reports those facts, as counts of fixed indicator names (never code):

* it runs the macro's own text-building code (vbaeval.py, nothing real is performed) and searches
  what comes out, so a command that only exists after the macro's decoder ran is still seen;
* it follows calls from every auto-run entry point (AutoOpen, Document_Open, Workbook_Open ...) and
  asks whether any of them reaches code that runs programs, downloads or injects;
* it looks at structure: Windows API imports that load or inject code, calls whose target is
  computed (CallByName, CreateObject(variable)), data read from places a macro should not need
  (document properties, form captions, custom XML), files written to temp or start-up folders, and
  how random the code looks (decoder-style Chr() chains, meaningless names, huge literals).

No single fact is a verdict. The host's rules combine them with the rest of the evidence.
"""

import re

import contentscan
import vbaeval
from limits import MAX_CONTENT_URLS, MAX_VBA_CHARS

# what an entry point must reach for it to count (the existing script indicators)
SINKS = (
    "exec_shell", "download", "execute_dynamic", "encoded_command", "lolbin_proxy",
    "process_injection", "persistence",
)  # fmt: skip
_DECLARE = re.compile(
    r"(?im)^\s*(?:public\s+|private\s+)?declare\s+(?:ptrsafe\s+)?(?:function|sub)\s+(\w+)\s+lib\s+"
    r'"([^"]+)"(?:\s+alias\s+"([^"]+)")?'
)
# Windows functions a macro uses to load code, run programs, fetch files or inject
_DANGEROUS_API = frozenset(
    {
        "virtualalloc", "virtualallocex", "virtualprotect", "rtlmovememory", "copymemory",
        "createthread", "createremotethread", "writeprocessmemory", "openprocess",
        "ntallocatevirtualmemory", "winexec", "shellexecute", "createprocess",
        "createprocessasuser",
        "urldownloadtofile", "urldownloadtocachefile", "loadlibrary", "loadlibraryex",
        "getprocaddress", "callwindowproc", "enumsystemlocales", "enumwindows", "enumchildwindows",
        "enumdesktopwindows", "enumuilanguages", "enumtimeformats", "createtimerqueuetimer",
        "queueuserapc", "ntqueueapcthread", "setwindowshookex", "internetopen", "internetopenurl",
        "internetreadfile", "httpsendrequest", "dllcanunloadnow", "createfilemapping",
    }
)  # fmt: skip
_DYNAMIC = re.compile(
    r"(?i)\bcallbyname\s*\(|\bapplication\s*\.\s*run\s*\(?\s*[^\"\s)]"
    r"|\bcreateobject\s*\(\s*[^\"\s)]|\bgetobject\s*\(\s*\"?\s*new\s*:"
    r"|\bexecuteexcel4macro\b|\bevaluate\s*\(\s*[^\"\s)]"
)
_HIDDEN_STORE = re.compile(
    r"(?i)\bbuiltindocumentproperties\b|\bcustomdocumentproperties\b|\bcustomxmlparts\b"
    r"|\.controltiptext\b|\.alternativetext\b|\bactivedocument\.variables\b"
    r"|\buserform\d*\.\w+\.(?:caption|text|value|tag)\b"
)
_WRITE = re.compile(
    r"(?i)\bopen\b[^\n]{0,160}\bfor\s+(?:binary|output|append)\b|\.savetofile\b|\bfilecopy\b"
)
_DROP_PATH = re.compile(
    r"(?i)environ\s*\(\s*\"?(?:temp|tmp|appdata|public|programdata)"
    r"|\\(?:temp|appdata|programdata|public)\\|\\startup\\|%(?:temp|appdata|programdata)%"
)
# VBA's own Shell statement written without brackets (Shell cmd, 0): it runs a program, and the
# script patterns only know the bracketed form. Not an assignment (Shell = ...), not a name that
# merely starts with the word (ShellPath), not an object (Shell.Run).
_VBA_SHELL = re.compile(
    r"(?im)(?:^|:|\bthen\b|\belse\b)[ \t]*(?:call[ \t]+)?shell[ \t]+(?!=)[^\s=]"
)
_STRING = re.compile(r'"(?:[^"]|"")*"')
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{6,}\b")
_CHR = re.compile(r"(?i)\bchrw?\$?\s*\(")
_ARRAY = re.compile(r"(?i)\barray\s*\(([^)]{0,20000})\)")


def _random_name(word: str) -> bool:
    letters = [c for c in word.lower() if c.isalpha()]
    if len(letters) < 5:
        return False
    vowels = sum(c in "aeiou" for c in letters) / len(letters)
    digits = sum(c.isdigit() for c in word)
    return vowels <= 0.15 or (digits >= 3 and len(letters) >= 4)


def _obfuscation_points(text: str, revealed: bool) -> int:
    """How many independent signs of machine-made or deliberately unreadable code there are."""
    code = _STRING.sub('""', text)
    names = set(_IDENT.findall(code))
    literal = sum(len(m) for m in _STRING.findall(text))
    points = 0
    points += len(_CHR.findall(text)) >= 15
    # a page or report builder is all quoted text and joins; that alone is not obfuscation
    points += text.count("&") >= 200 and literal / max(len(text), 1) >= 0.8
    points += len(names) >= 8 and sum(_random_name(n) for n in names) / len(names) >= 0.5
    points += any(len(a.split(",")) >= 40 for a in _ARRAY.findall(text))
    points += any(len(line) >= 1500 for line in text.splitlines())
    return points + (1 if revealed else 0)


def _api_imports(text: str) -> int:
    n = 0
    for name, _lib, alias in _DECLARE.findall(text):
        for word in (name, alias):
            base = word.lower()
            if base in _DANGEROUS_API or base.rstrip("aw") in _DANGEROUS_API:
                n += 1
                break
    return n


def analyze(sources: list[str], st: contentscan._State) -> None:  # noqa: SLF001
    """Add what the macro's code gives away to `st` (see the module text)."""
    text = "\n".join(sources)[:MAX_VBA_CHARS]
    if not text.strip():
        return
    try:
        prog = vbaeval.Program(text)
        ev = vbaeval.run(prog)
    except Exception:  # noqa: BLE001  (hostile input: a bug here must not fail the file's scan)
        prog, ev = None, None
    plain = contentscan._State()  # noqa: SLF001
    contentscan._scan_text(text, plain, 0)  # noqa: SLF001  (what the text says on its face)
    revealed = False
    if prog is not None and ev is not None:
        built = contentscan._State()  # noqa: SLF001
        for s in ev.strings:
            contentscan._scan_text(s, built, 1)  # noqa: SLF001
        hidden = [
            n for n in built.counts if n in contentscan.INDICATORS and not plain.counts.get(n)
        ]
        for name, n in built.counts.items():
            st.add(name, n)
        for url in built.urls:
            if url not in st.urls and len(st.urls) < MAX_CONTENT_URLS:
                st.urls.append(url)
        for kind, n in built.embedded.items():
            st.embedded[kind] = st.embedded.get(kind, 0) + n
        st.truncated = st.truncated or ev.truncated or built.truncated
        if hidden:
            revealed = True
            st.add("macro_hidden_behavior", len(hidden))
            st.layers = max(st.layers, built.layers, 1)
        reached = 0
        for entry in (n for n in prog.procs if n in vbaeval.AUTOEXEC):
            seen: set[str] = set()
            stack = [entry]
            while stack:
                p = stack.pop()
                if p in seen:
                    continue
                seen.add(p)
                stack += [w for w in prog.procs[p].ids if w in prog.procs and w not in seen]
            blob = "\n".join(prog.procs[p].text for p in seen)
            blob += "\n" + "\n".join(ev.by_root.get(entry, []))
            probe = contentscan._State()  # noqa: SLF001
            contentscan._scan_text(blob, probe, 0)  # noqa: SLF001
            reached += any(probe.counts.get(n) for n in SINKS) or bool(_VBA_SHELL.search(blob))
        if reached:
            st.add("macro_autoexec_reaches_sink", reached)
    if n := len(_VBA_SHELL.findall("\n".join(vbaeval.logical_lines(text)))):
        st.add("exec_shell", n)
    norm, _ = contentscan.normalize(text)
    if n := _api_imports(norm):
        st.add("win32_api_import", n)
    if n := len(_DYNAMIC.findall(norm)):
        st.add("macro_dynamic_dispatch", n)
    if n := len(_HIDDEN_STORE.findall(norm)):
        st.add("macro_hidden_data_source", n)
    if _WRITE.search(norm) and _DROP_PATH.search(norm):
        st.add("macro_file_drop")
    if _obfuscation_points(text, revealed) >= 2:
        st.add("macro_obfuscated_code")


def excerpt(sources: list[str], limit: int = 12_000) -> str:
    """The macro as one bounded block of plain text for a human-style reader (the local model):
    comments dropped (they are where a prompt injection would hide), common disguises undone, and
    the strings the macro builds when its own decoders run, appended."""
    text = "\n".join(sources)[:MAX_VBA_CHARS]
    code = "\n".join(vbaeval.logical_lines(text))
    norm, _ = contentscan.normalize(code)
    try:
        built = vbaeval.evaluate(text).strings
    except Exception:  # noqa: BLE001
        built = []
    tail = ""
    if built:
        tail = "\n' --- strings this macro builds when its own decoders run ---\n" + "\n".join(
            s[:300] for s in built[:40]
        )
    out = norm[: max(limit - len(tail), 1000)] + tail
    return "".join(c if c in "\n\t" or 32 <= ord(c) < 127 else " " for c in out)[:limit]
