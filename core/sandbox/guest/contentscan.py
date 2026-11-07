"""Look INSIDE a file: what kind of program text it is, what that text does, and what is hidden in
it. Standard library only; runs inside the sandbox on hostile input.

Nothing is executed or evaluated: the text is only searched. Common ways of hiding code are undone
first, with hard bounds on every step (see limits.py): string pieces are joined ("Sh" & "ell"),
character codes are turned back into letters (Chr(87), String.fromCharCode, [char]87), escapes and
backticks are removed, and encoded blocks (Base64, hex, deflated Base64, PowerShell's UTF-16
-EncodedCommand) are decoded and searched again, up to MAX_LAYERS deep. What is found is reported as
counts of a closed set of indicator names, never as text, so the host's rules see facts and the
database never stores code. URLs found in the code are returned so the URL engine can judge them.
"""

import base64
import binascii
import math
import re
import zlib
from typing import Any

from limits import (
    MAX_BLOBS,
    MAX_CONTENT_BYTES,
    MAX_CONTENT_CHARS,
    MAX_CONTENT_URLS,
    MAX_LAYERS,
    MAX_SCAN_DECODED_TOTAL,
)

PROGRAM = {"vbscript", "jscript", "powershell", "batch", "hta", "wsf", "html"}
# the industry's harmless antivirus test string, in two pieces so this file never contains it whole
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# ---- what kind of text is it? ------------------------------------------------------------------
_HINTS = {
    "hta": re.compile(
        r"(?i)<hta:application|<script[^>]{0,80}language\s*=\s*[\"']?(?:vbscript|jscript)"
    ),
    "wsf": re.compile(r"(?i)<job\b|<package\b|<scriptlet\b"),
    "vbscript": re.compile(
        r"(?im)\bwscript\.|\bcreateobject\s*\(|on\s+error\s+resume\s+next|^\s*dim\s+\w+"
        r"|^\s*set\s+\w+\s*=\s*createobject|\bmsgbox\b|\bend\s+(?:sub|function|if)\b"
    ),
    "jscript": re.compile(
        r"(?i)\bactivexobject\b|\bwscript\.(?:echo|shell|createobject)|\bfunction\s+\w*\s*\("
        r"|\bvar\s+\w+\s*=|\beval\s*\(|\bunescape\s*\(|\bfromcharcode\b|=>\s*\{"
    ),
    "powershell": re.compile(
        r"(?i)\$[a-z_]\w*\s*=|\bparam\s*\(|\bwrite-(?:host|output)\b|\bnew-object\b"
        r"|\binvoke-(?:expression|webrequest|command)\b|\bget-[a-z]+\b|\bset-[a-z]+\b"
        r"|\[(?:system|convert|text|io|reflection)\.[a-z.]+\]|\b(?:powershell|pwsh)(?:\.exe)?\s+-"
    ),
    "batch": re.compile(
        r"(?im)^\s*@?echo\s+off|^\s*setlocal\b|^\s*(?:goto|call)\s+[:\w]|%comspec%"
        r"|\bcmd(?:\.exe)?\s+/[ck]\b|^\s*if\s+(?:not\s+)?(?:exist|defined|errorlevel)\b"
        r"|^\s*for\s+/?[a-z]?\s+%%?\w"
    ),
}
_FAMILY_ORDER = ("hta", "wsf", "powershell", "vbscript", "jscript", "batch")

# ---- what does it do? --------------------------------------------------------------------------
# Every pattern is linear: no nested quantifiers, bounded gaps. Matched against the text as written
# and against the text with the usual disguises removed; the larger count counts.

_I = re.IGNORECASE
INDICATORS: dict[str, re.Pattern[str]] = {
    "exec_shell": re.compile(
        r"wscript\.shell|shell\.application|\.shellexecute\b|\bcreateprocess|\bstart-process\b"
        r"|\bcmd(?:\.exe)?\s+/[ck]\b|\bwmic\b[^\n]{0,40}process\s+call\s+create|win32_process\b"
        r"|\binvoke-item\b|\.exec\s*\(|\bos\.system\b|\bshell\s*\(",
        _I,
    ),
    "download": re.compile(
        r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b"
        r"|invoke-restmethod|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp"
        r"|adodb\.stream|\bbitsadmin\b|start-bitstransfer|certutil[^\n]{0,60}-urlcache"
        r"|urldownloadtofile|\bcurl(?:\.exe)?\s+-|\bwget\s",
        _I,
    ),
    "execute_dynamic": re.compile(
        r"\bexecuteglobal\b|\bexecute\s*[(\"']|\beval\s*\(|\binvoke-expression\b|\biex\b"
        r"|\bnew\s+function\s*\(|\bsettimeout\s*\(\s*[\"']|\[scriptblock\]::create|\badd-type\b",
        _I,
    ),
    "encoded_command": re.compile(
        r"\s-(?:e|ec|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm"
        r"|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{16,}",
        _I,
    ),
    "base64_decode": re.compile(
        r"frombase64string|certutil[^\n]{0,60}-decode|\batob\s*\(|base64binary|bin\.base64",
        _I,
    ),
    "hidden_window": re.compile(
        r"-w(?:indowstyle)?\s+hidden|\bvbhide\b|\.run\s*[^\n]{0,200},\s*0\b|createnowindow"
        r"|windowstyle\s*=\s*0",
        _I,
    ),
    "bypass_policy": re.compile(
        r"-ex(?:ecutionpolicy)?\s+(?:bypass|unrestricted)\b|-ep\s+bypass\b", _I
    ),
    "persistence": re.compile(
        r"\\currentversion\\run(?:once)?\b|schtasks(?:\.exe)?\s+/create"
        r"|\\start menu\\programs\\startup|__eventfilter|__eventconsumer"
        r"|\breg(?:\.exe)?\s+add\b|register-scheduledtask|new-scheduledtask"
        r"|\bsc(?:\.exe)?\s+create\b",
        _I,
    ),
    "lolbin_proxy": re.compile(
        r"\bmshta(?:\.exe)?\b|regsvr32(?:\.exe)?\s+[^\n]{0,40}/i:"
        r"|rundll32(?:\.exe)?\s+[^\n]{0,40}(?:javascript:|vbscript:)|\bcmstp(?:\.exe)?\b"
        r"|\binstallutil(?:\.exe)?\b|\bodbcconf\b|msiexec(?:\.exe)?\s+[^\n]{0,20}/[iq][^\n]{0,60}https?://"
        r"|\bwmic\b[^\n]{0,20}/format:|\bforfiles\b[^\n]{0,40}/c\b|\bpcalua\b",
        _I,
    ),
    "defense_evasion": re.compile(
        r"amsiutils|amsiinitfailed|amsiscanbuffer|add-mppreference\s+-exclusion"
        r"|set-mppreference[^\n]{0,40}disable|disableantispyware|wevtutil(?:\.exe)?\s+cl\b"
        r"|clear-eventlog|stop-service\s+[^\n]{0,20}(?:windefend|sense)|tamperprotection",
        _I,
    ),
    "process_injection": re.compile(
        r"\bvirtualalloc(?:ex)?\b|writeprocessmemory|createremotethread|ntallocatevirtualmemory"
        r"|rtlmovememory|queueuserapc|setthreadcontext|ntcreatethreadex|\bvirtualprotect\b",
        _I,
    ),
    "credential_access": re.compile(
        r"sekurlsa|mimikatz|\blsass(?:\.exe)?\b|comsvcs\.dll[^\n]{0,20}minidump|\bntds\.dit\b",
        _I,
    ),
    "credential_prompt": re.compile(
        r"promptforcredential|\bget-credential\b|credentialpicker|inputbox\s*\([^\n]{0,120}pass",
        _I,
    ),
    "anti_analysis": re.compile(
        r"vboxservice|vmtoolsd|\bvmware\b|\bvirtualbox\b|\bqemu\b|sbiedll|isdebuggerpresent"
        r"|checkremotedebuggerpresent|win32_bios|win32_computersystem[^\n]{0,60}(?:model|manufacturer)"
        r"|start-sleep\s+-s(?:econds)?\s+\d{2,}|\bping(?:\.exe)?\s+(?:-n|/n)\s+\d{2,}",
        _I,
    ),
}

# ---- undoing common disguises ------------------------------------------------------------------
_JOIN = re.compile(r"""["']\s*[&+]\s*["']""")  # "Sh" & "ell"  ->  "Shell" (any mix of quotes)
_CHR = re.compile(r"(?i)\bchrw?\$?\(\s*(&h[0-9a-f]{1,4}|\d{1,5})\s*\)")  # VBScript
_FROMCHARCODE = re.compile(
    r"(?i)string\.fromcharcode\(\s*((?:(?:0x[0-9a-f]{1,4}|\d{1,5})\s*,\s*){0,300}"
    r"(?:0x[0-9a-f]{1,4}|\d{1,5}))\s*\)"
)
_PS_CHAR = re.compile(r"(?i)\[char\]\s*(0x[0-9a-f]{1,4}|\d{1,5})")  # PowerShell
_PS_CHARS = re.compile(
    r"(?i)\[char\[\]\]\s*\(?\s*((?:(?:0x[0-9a-f]{1,4}|\d{1,5})\s*,\s*){0,300}(?:0x[0-9a-f]{1,4}|\d{1,5}))\s*\)?"
)
_ESC_X = re.compile(r"\\x([0-9a-fA-F]{2})")
_ESC_U = re.compile(r"\\u([0-9a-fA-F]{4})")
_ESC_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_BACKTICK = re.compile(r"`(?=[A-Za-z0-9])")
_CARET = re.compile(r"\^(?=[^\r\n])")


def _ch(n: int) -> str:
    return chr(n) if 32 <= n < 127 or n in (9, 10, 13) else ""


def _quote(text: str) -> str:
    return '"' + text.replace('"', "'") + '"' if text else ""


def _number(token: str) -> int:
    token = token.strip()
    if token[:2].lower() in ("&h", "0x"):
        return int(token[2:], 16)
    return int(token)


def normalize(text: str) -> tuple[str, int]:
    """The text with the usual disguises undone, and how many disguises were undone."""
    hits = 0

    def sub(pattern: re.Pattern[str], repl: Any) -> None:
        nonlocal text, hits
        text, n = pattern.subn(repl, text)
        hits += n

    sub(_CHR, lambda m: _quote(_ch(_number(m.group(1)))))
    sub(_FROMCHARCODE, lambda m: _quote("".join(_ch(_number(t)) for t in m.group(1).split(","))))
    sub(_PS_CHARS, lambda m: _quote("".join(_ch(_number(t)) for t in m.group(1).split(","))))
    sub(_PS_CHAR, lambda m: _quote(_ch(_number(m.group(1)))))
    sub(_ESC_X, lambda m: _ch(int(m.group(1), 16)) or m.group(0))
    sub(_ESC_U, lambda m: _ch(int(m.group(1), 16)) or m.group(0))
    sub(
        _ESC_PCT,
        lambda m: "".join(_ch(int(h, 16)) or "%" + h for h in m.group(0)[1:].split("%")),
    )
    sub(_BACKTICK, "")
    sub(_CARET, "")
    for _ in range(4):  # "a" & "b" & "c" needs more than one pass
        text, n = _JOIN.subn("", text)
        hits += n
        if not n:
            break
    return text, hits


# ---- decoding hidden blocks --------------------------------------------------------------------
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}){32,}")
_URL = re.compile(r"https?://[^\s'\"<>)\]}\\^`]{4,2000}", re.IGNORECASE)
_BLOB_FLAG = 2000  # characters of one encoded block that count as "a block of hidden data"


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data[:4096] if 32 <= b < 127 or b in (9, 10, 13))
    return ok / min(len(data), 4096)


def to_text(data: bytes) -> str:
    """Program text from bytes: UTF-16 (a BOM, or NULs between the letters) or UTF-8."""
    head = data[:4096]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encoding = "utf-16"
    elif head and head.count(b"\x00") > len(head) // 4:
        encoding = "utf-16-le" if head[1:2] == b"\x00" else "utf-16-be"
    else:
        encoding = "utf-8"
    return data[:MAX_CONTENT_BYTES].decode(encoding, "replace")[:MAX_CONTENT_CHARS]


def _inflate(data: bytes) -> bytes | None:
    """Raw deflate or zlib, as PowerShell loaders use; never more than the decoded budget."""
    for wbits in (-15, 15):
        try:
            out = zlib.decompressobj(wbits).decompress(data, MAX_SCAN_DECODED_TOTAL)
        except zlib.error:
            continue
        if out:
            return out
    return None


class _State:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.urls: list[str] = []
        self.embedded: dict[str, int] = {}
        self.layers = 0
        self.obfuscation = 0
        self.left = MAX_SCAN_DECODED_TOTAL
        self.seen: set[bytes] = set()
        self.truncated = False

    def add(self, name: str, n: int = 1) -> None:
        self.counts[name] = min(self.counts.get(name, 0) + n, 10_000)

    def take_urls(self, text: str) -> None:
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:")
            if url not in self.urls and len(self.urls) < MAX_CONTENT_URLS:
                self.urls.append(url)


def _decode_blobs(text: str, st: _State, depth: int) -> None:
    candidates: list[bytes] = []
    for m in _B64.finditer(text):
        if len(candidates) >= MAX_BLOBS:
            st.truncated = True
            break
        raw = m.group(0)
        if len(raw) >= _BLOB_FLAG:
            st.add("high_entropy_blob")
        try:
            padded = raw + "=" * (-len(raw) % 4)
            candidates.append(base64.b64decode(padded, validate=False))
        except (binascii.Error, ValueError):
            continue
    for m in _HEX.finditer(text):
        if len(candidates) >= MAX_BLOBS * 2:
            st.truncated = True
            break
        if len(m.group(0)) >= _BLOB_FLAG:
            st.add("high_entropy_blob")
        try:
            candidates.append(bytes.fromhex(m.group(0)))
        except ValueError:
            continue
    for blob in candidates:
        if st.left <= 0:
            st.truncated = True
            return
        if blob in st.seen or len(blob) < 16:
            continue
        st.seen.add(blob)
        st.left -= len(blob)
        _inspect_decoded(blob, st, depth)


def _inspect_decoded(blob: bytes, st: _State, depth: int) -> None:
    inflated = _inflate(blob)
    for data in (blob, inflated):
        if data is None:
            continue
        if data.startswith(b"MZ"):
            st.embedded["exe"] = st.embedded.get("exe", 0) + 1
            st.layers = max(st.layers, depth + 1)
            return
        if data.startswith(b"\x7fELF"):
            st.embedded["elf"] = st.embedded.get("elf", 0) + 1
            st.layers = max(st.layers, depth + 1)
            return
        if data.startswith((b"PK\x03\x04", b"\xd0\xcf\x11\xe0")):
            st.embedded["zip"] = st.embedded.get("zip", 0) + 1
            st.layers = max(st.layers, depth + 1)
            return
        text = to_text(data)
        if len(text) >= 8 and _printable_ratio(text.encode("utf-8", "replace")) >= 0.9:
            st.layers = max(st.layers, depth + 1)
            _scan_text(text, st, depth + 1)
            return


def _scan_text(text: str, st: _State, depth: int) -> None:
    norm, hits = normalize(text)
    st.obfuscation += hits
    for name, pattern in INDICATORS.items():
        n = max(len(pattern.findall(text)), len(pattern.findall(norm)))
        if n:
            st.add(name, n)
    st.take_urls(norm)
    if depth < MAX_LAYERS:
        _decode_blobs(norm, st, depth)
    else:
        st.truncated = True


# ---- entry points ------------------------------------------------------------------------------
def entropy(data: bytes) -> float:
    sample = data[:MAX_CONTENT_BYTES]
    if not sample:
        return 0.0
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    total = len(sample)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def detect_family(text: str) -> str:
    scores = {name: len(_HINTS[name].findall(text[:100_000])) for name in _FAMILY_ORDER}
    for name in ("hta", "wsf"):
        if scores[name]:
            return name
    best = max(_FAMILY_ORDER[2:], key=lambda n: scores[n])
    return best if scores[best] >= 2 else "text"


STRONG = (
    "encoded_command",
    "lolbin_proxy",
    "defense_evasion",
    "process_injection",
    "credential_access",
)
_POWERSHELL_WORD = re.compile(r"(?i)\b(?:powershell|pwsh)\b")


def scan_text_file(data: bytes, family_hint: str | None = None) -> dict[str, Any]:
    text = to_text(data)
    family = family_hint or detect_family(text)
    st = _State()
    if family in PROGRAM:
        _scan_text(text, st, 0)
    else:
        # Plain text is searched too, but only a command line that is clearly hostile (an encoded
        # command, a trusted program used as a proxy, ...) turns it into a program: a note that
        # merely says "download" must not be called a script.
        probe = _State()
        _scan_text(text, probe, 0)
        if any(probe.counts.get(name) for name in STRONG):
            family = "powershell" if _POWERSHELL_WORD.search(text) else "batch"
            st = probe
        else:
            st.take_urls(text)
    if st.obfuscation >= 10:
        st.add("string_obfuscation", st.obfuscation)
    # a program-looking file that carries an executable it did not declare
    if data[:2] != b"MZ" and b"This program cannot be run in DOS mode" in data[:MAX_CONTENT_BYTES]:
        st.embedded["exe"] = st.embedded.get("exe", 0) + 1
    return result(data, family, st)


def result(data: bytes, family: str, st: _State) -> dict[str, Any]:
    return {
        "kind": "content",
        "family": family,
        "truncated": st.truncated or len(data) > MAX_CONTENT_BYTES,
        "indicators": dict(sorted(st.counts.items())),
        "layers": st.layers,
        "embedded": dict(sorted(st.embedded.items())),
        "urls": st.urls,
        "entropy": round(entropy(data), 2),
        "eicar": data[:128].lstrip().startswith(EICAR),
    }


def looks_like_text(data: bytes) -> bool:
    head = data[:4096]
    if not head:
        return False
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or head.count(b"\x00") > len(head) // 4:
        return True
    return _printable_ratio(head) >= 0.9


def scan_content(data: bytes, magic: str | None) -> dict[str, Any]:
    """The deep scan of one file, chosen by what it IS. A kind with no scanner here answers
    `{"kind": "none"}` so the caller can say so."""
    found: dict[str, Any] = {"kind": "none"}
    if magic == "lnk":
        import lnkscan

        found = lnkscan.scan_lnk(data)
    elif magic == "exe":
        import pescan

        found = pescan.scan_pe(data)
    elif magic == "ole":
        import olescan

        found = olescan.scan_ole(data)
    elif magic == "rtf":
        import olescan

        found = olescan.scan_rtf(data)
    elif magic in ("html", "svg"):
        found = scan_text_file(data, "html")
    elif magic is None and looks_like_text(data):
        found = scan_text_file(data)
    return found
