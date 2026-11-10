"""Old-format Office files (OLE compound files) and RTF, read by the published layouts. Standard
library only; runs inside the sandbox on hostile input.

For a compound file (MS-CFB) the directory is walked, the macro project's `dir` stream and its
modules are read, and the macro source is recovered with the published decompression (MS-OVBA).
That source is searched like any script. Nothing is opened as a document and no macro is run.
"""

import math
import re
import struct
from typing import Any

import contentscan
import vbaanalyze
from limits import MAX_CONTENT_BYTES, MAX_OLE_STREAMS, MAX_VBA_CHARS

_END = 0xFFFFFFFE
_FREE = 0xFFFFFFFF
_MAX_STREAM = 4 * 1024 * 1024
_MAX_TOTAL = 12 * 1024 * 1024
_AUTOEXEC = re.compile(
    r"(?i)\b(?:auto_?open|auto_?exec|auto_?close|auto_?new|document_(?:open|close|new)"
    r"|workbook_(?:open|activate)|auto_?activate)\b"
)


def _u32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<I", data, at)[0])


class _Cfb:
    """Just enough of the compound file format to list streams and read them."""

    def __init__(self, data: bytes) -> None:
        if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or len(data) < 512:
            raise ValueError("not a compound file")
        self.data = data
        shift, mini_shift = struct.unpack_from("<HH", data, 30)
        if shift not in (9, 12) or mini_shift != 6:
            raise ValueError("odd sector sizes")
        self.size = 1 << shift
        (self.dir_start,) = struct.unpack_from("<I", data, 48)
        self.cutoff = _u32(data, 56)
        mini_start, n_mini, difat_start, n_difat = struct.unpack_from("<IIII", data, 60)
        sectors = max(len(data) // self.size, 1)
        difat = list(struct.unpack_from("<109I", data, 76))
        sid, hops = difat_start, 0
        while sid not in (_END, _FREE) and hops < min(n_difat, 200) and sid < sectors:
            block = self._sector(sid)
            difat += list(struct.unpack_from(f"<{self.size // 4}I", block))[:-1]
            sid = _u32(block, self.size - 4)
            hops += 1
        self.fat: list[int] = []
        for fat_sid in difat:
            if fat_sid >= sectors or len(self.fat) > 400_000:
                continue
            self.fat += struct.unpack_from(f"<{self.size // 4}I", self._sector(fat_sid))
        self.minifat: list[int] = []
        if mini_start not in (_END, _FREE) and n_mini:
            raw = self._chain(mini_start, self.size * min(n_mini, 4096))
            self.minifat = list(struct.unpack_from(f"<{len(raw) // 4}I", raw[: len(raw) // 4 * 4]))
        self.ministream = b""

    def _sector(self, sid: int) -> bytes:
        start = (sid + 1) * self.size
        block = self.data[start : start + self.size]
        if len(block) < self.size:
            raise ValueError("sector past the end")
        return block

    def _chain(self, start: int, limit: int) -> bytes:
        out: list[bytes] = []
        seen: set[int] = set()
        sid = start
        total = 0
        while (
            sid not in (_END, _FREE) and sid < len(self.fat) and sid not in seen and total < limit
        ):
            seen.add(sid)
            try:
                out.append(self._sector(sid))
            except ValueError:
                break
            total += self.size
            sid = self.fat[sid]
        return b"".join(out)[:limit]

    def _mini_chain(self, start: int, size: int) -> bytes:
        out: list[bytes] = []
        seen: set[int] = set()
        sid = start
        while (
            sid not in (_END, _FREE)
            and sid < len(self.minifat)
            and sid not in seen
            and len(out) < 70_000
        ):
            seen.add(sid)
            out.append(self.ministream[sid * 64 : sid * 64 + 64])
            sid = self.minifat[sid]
        return b"".join(out)[:size]

    def streams(self) -> dict[str, bytes]:
        raw = self._chain(self.dir_start, 128 * MAX_OLE_STREAMS)
        entries = []
        for i in range(0, len(raw) - 127, 128):
            e = raw[i : i + 128]
            n = min(struct.unpack_from("<H", e, 64)[0], 64)
            name = e[: max(n - 2, 0)].decode("utf-16-le", "replace")
            kind = e[66]
            left, right, child = struct.unpack_from("<III", e, 68)
            start = _u32(e, 116)
            size = _u32(e, 120)
            entries.append((name, kind, left, right, child, start, size))
        if not entries:
            return {}
        root = entries[0]
        self.ministream = self._chain(root[5], min(root[6], _MAX_TOTAL))
        out: dict[str, bytes] = {}
        budget = _MAX_TOTAL

        def walk(index: int, prefix: str, depth: int) -> None:
            nonlocal budget
            if index >= len(entries) or index in visited or depth > 40 or budget <= 0:
                return
            visited.add(index)
            name, kind, left, right, child, start, size = entries[index]
            walk(left, prefix, depth + 1)
            path = f"{prefix}{name}"
            if kind == 2:
                size = min(size, _MAX_STREAM, budget)
                body = (
                    self._mini_chain(start, size)
                    if size < self.cutoff
                    else self._chain(start, size)
                )
                out[path] = body
                budget -= len(body)
            elif kind == 1:
                walk(child, path + "/", depth + 1)
            walk(right, prefix, depth + 1)

        visited: set[int] = {0}
        walk(root[4], "", 0)
        return out


def ovba_decompress(buf: bytes) -> bytes:
    """MS-OVBA 2.4.1: the compressed container of a module's source."""
    if not buf or buf[0] != 1:
        return b""
    out = bytearray()
    pos = 1
    while pos + 2 <= len(buf) and len(out) < MAX_VBA_CHARS:
        header = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
        chunk_end = min(pos - 2 + (header & 0x0FFF) + 3, len(buf))
        chunk_start = len(out)
        if not header & 0x8000:  # stored, not compressed
            out += buf[pos : pos + 4096]
            pos = chunk_end
            continue
        while pos < chunk_end:
            flags = buf[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not (flags >> bit) & 1:
                    out.append(buf[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    pos = chunk_end
                    break
                token = struct.unpack_from("<H", buf, pos)[0]
                pos += 2
                done = len(out) - chunk_start
                bits = max(math.ceil(math.log2(done)) if done > 1 else 0, 4)
                length = (token & (0xFFFF >> bits)) + 3
                offset = (token >> (16 - bits)) + 1
                if offset > done:
                    return bytes(out)  # a copy from before the chunk: damaged, stop here
                for _ in range(length):
                    out.append(out[-offset])
        pos = chunk_end
    return bytes(out)


def _vba_modules(streams: dict[str, bytes]) -> list[tuple[str, int]]:
    """Module stream names and where their source starts, from the project's `dir` stream."""
    for path, body in streams.items():
        if path.lower().endswith("vba/dir"):
            directory = ovba_decompress(body)
            break
    else:
        return []
    modules: list[tuple[str, int]] = []
    pos, stream_name = 0, ""
    while pos + 6 <= len(directory):
        record, size = struct.unpack_from("<HI", directory, pos)
        pos += 6
        if record == 0x0009:  # PROJECTVERSION is the one record whose size field lies
            size = 6
        body = directory[pos : pos + size]
        pos += size
        if record == 0x001A:
            stream_name = body.decode("cp1252", "replace")
        elif record == 0x0031 and len(body) == 4 and stream_name:
            modules.append((stream_name, struct.unpack("<I", body)[0]))
    return modules[:100]


# ---- compiled code that does not match the source (VBA stomping) -------------------------------
_PCODE_RUN = re.compile(rb"[\x20-\x7e]{10,200}")
_PCODE_HIT = re.compile(
    r"(?i)powershell|cmd(?:\.exe)?\s*/|https?://|wscript|createobject|\.exe\b|\bshell\b|mshta"
    r"|regsvr32|certutil|bitsadmin|urldownloadtofile"
)


def _pcode_checks(pcode: bytes, source: str, st: Any) -> None:
    """A module is stored twice: as source text and as compiled "p-code" that Office runs when its
    version matches. An attacker can keep harmless source and ship different p-code ("stomping"), or
    ship no source at all. Neither can be seen by reading the source, so the compiled part's text is
    compared with it: a command word the compiled part contains and the source does not, or a
    large compiled part with an empty source, is reported (and what the compiled part says is
    searched)."""
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().lower().startswith("attribute ")
    ).strip()
    low = code.lower()
    stomped = 0
    for m in _PCODE_RUN.finditer(pcode[:200_000]):
        run = m.group(0).decode("ascii")
        hit = _PCODE_HIT.search(run)
        if hit and hit.group(0).lower() not in low:
            stomped += 1
            contentscan._scan_text(run, st, 1)  # noqa: SLF001
    if len(pcode) >= 1500 and not code:
        st.add("vba_pcode_only")
    if stomped and code:
        st.add("vba_stomped", min(stomped, 10))


# ---- Excel 4.0 (XLM) macro sheets in the old binary format --------------------------------------
def _scan_biff(streams: dict[str, bytes], st: Any) -> None:
    """The workbook's sheet list: a sheet of type "macro" is an Excel 4.0 macro (formulas that can
    run programs, no VBA involved), and a hidden one is how it is usually shipped. A built-in name
    Auto_Open makes it run when the file is opened."""
    book = next((b for p, b in streams.items() if p.lower() in ("workbook", "book")), b"")
    pos, macro, hidden, auto, seen = 0, 0, 0, False, 0
    while pos + 4 <= len(book) and seen < 20_000:
        rid, size = struct.unpack_from("<HH", book, pos)
        data = book[pos + 4 : pos + 4 + size]
        pos += 4 + size
        seen += 1
        if rid == 0x000A:  # EOF of the workbook-global part: the sheets are listed before it
            break
        if rid == 0x0085 and len(data) >= 8 and data[5] == 1:  # BoundSheet8, sheet type "macro"
            macro += 1
            hidden += (data[4] & 3) != 0
        elif rid == 0x0018 and len(data) >= 16:  # Lbl: a defined name
            built_in = struct.unpack_from("<H", data, 0)[0] & 0x20 and data[3] == 1
            auto = auto or bool(built_in and data[15] == 1)  # name 1 = Auto_Open
    if macro:
        st.add("xlm_macro", macro)
        st.add("macro_code")
        if hidden:
            st.add("xlm_hidden", hidden)
        if auto:
            st.add("autoexec")


def macro_sources(data: bytes) -> list[str]:
    """The readable VBA source of every module of an old-format Office file (for a reader that is
    not this scanner: the local model). Empty when there is none."""
    try:
        streams = _Cfb(data).streams()
    except (ValueError, struct.error, IndexError, RecursionError):
        return []
    out: list[str] = []
    for stream_name, offset in _vba_modules(streams):
        body = next(
            (b for p, b in streams.items() if p.lower().endswith("vba/" + stream_name.lower())), b""
        )
        source = ovba_decompress(body[offset:]).decode("cp1252", "replace")[:MAX_VBA_CHARS]
        if source.strip():
            out.append(source)
    return out


def scan_ole(data: bytes) -> dict[str, Any]:
    st = contentscan._State()  # noqa: SLF001
    try:
        streams = _Cfb(data).streams()
    except (ValueError, struct.error, IndexError, RecursionError):
        return _done(data, "ole", st)
    names = [p.lower() for p in streams]
    has_vba = any(
        p.endswith("vba/dir") or "/vba/" in "/" + p or p.startswith("vba/") for p in names
    )
    source_found = False
    sources: list[str] = []
    if has_vba:
        for stream_name, offset in _vba_modules(streams):
            body = next(
                (b for p, b in streams.items() if p.lower().endswith("vba/" + stream_name.lower())),
                b"",
            )
            source = ovba_decompress(body[offset:]).decode("cp1252", "replace")[:MAX_VBA_CHARS]
            _pcode_checks(body[:offset], source, st)
            if not source.strip():
                continue
            source_found = True
            sources.append(source)
            if _AUTOEXEC.search(source):
                st.add("autoexec", len(_AUTOEXEC.findall(source)))
            contentscan._scan_text(source, st, 0)  # noqa: SLF001
        if sources:
            vbaanalyze.analyze(sources, st)
    _scan_biff(streams, st)
    if has_vba or source_found:
        st.add("macro_code")
    if any(n.endswith(("ole10native", "package")) or n.startswith("objectpool/") for n in names):
        st.add("ole_object")
    if any("equation native" in n for n in names):
        st.add("equation_editor")
    if st.obfuscation >= 10:
        st.add("string_obfuscation", st.obfuscation)
    return _done(data, "ole", st)


_RTF_OBJDATA = re.compile(rb"\\objdata\b")
_RTF_EQUATION = re.compile(rb"\\objclass\s+equation", re.IGNORECASE)
_RTF_TEMPLATE = re.compile(rb"\\\*\\template\s+(https?://[^}\s]{4,500})", re.IGNORECASE)
_RTF_LINK = re.compile(rb"\\(?:objautlink|objlink)\b")


def scan_rtf(data: bytes) -> dict[str, Any]:
    st = contentscan._State()  # noqa: SLF001
    sample = data[:MAX_CONTENT_BYTES]
    objects = len(_RTF_OBJDATA.findall(sample)) + len(_RTF_LINK.findall(sample))
    if objects:
        st.add("ole_object", objects)
    if _RTF_EQUATION.search(sample):
        st.add("equation_editor")
    for m in _RTF_TEMPLATE.finditer(sample):
        st.add("remote_template")
        st.take_urls(m.group(1).decode("ascii", "replace"))
    return _done(data, "rtf", st)


def _done(data: bytes, family: str, st: Any) -> dict[str, Any]:
    out: dict[str, Any] = contentscan.result(data, family, st)
    return out
