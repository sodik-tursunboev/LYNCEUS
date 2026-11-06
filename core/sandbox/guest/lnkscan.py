"""Windows shortcut (.lnk) files, read by the published layout (MS-SHLLINK). Standard library only.

A shortcut is a favourite way to start a script from an archive or a mail: its icon says
"document", its target is cmd.exe or powershell.exe, and the real command is a long argument string,
often padded with blanks so the properties window does not show it. We read the target, the
arguments and the icon and run the arguments through the same text scanner as a script. Nothing is
followed or started.
"""

import re
import struct
from typing import Any

import contentscan

_INTERPRETERS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "bitsadmin.exe", "certutil.exe", "wmic.exe",
    "forfiles.exe", "conhost.exe", "schtasks.exe", "curl.exe",
}  # fmt: skip
_ICON_LURES = re.compile(r"(?i)imageres\.dll|shell32\.dll|\.ico\b|wordpad\.exe|\.pdf\b|\.docx?\b")
_PADDING = re.compile(r"[ \t\r\n]{20,}")
_STRING_FIELDS = (
    (0x04, "name"),
    (0x08, "relative"),
    (0x10, "workdir"),
    (0x20, "args"),
    (0x40, "icon"),
)


def _local_base_path(data: bytes, pos: int) -> str:
    """The target path from LinkInfo, when the link points at a local file."""
    try:
        header_size, _, flags, _vol, base_offset = struct.unpack("<IIIII", data[pos : pos + 20])
        if not flags & 1 or base_offset == 0 or base_offset >= header_size + 4096:
            return ""
        raw = data[pos + base_offset : pos + base_offset + 520]
        return raw.split(b"\x00", 1)[0].decode("cp1252", "replace")
    except struct.error:
        return ""


def scan_lnk(data: bytes) -> dict[str, Any]:
    st = contentscan._State()  # noqa: SLF001  (one module family, one state type)
    try:
        if struct.unpack("<I", data[:4])[0] != 0x4C:
            return {"kind": "none"}
        flags = struct.unpack("<I", data[20:24])[0]
        pos = 76
        target = ""
        if flags & 0x01:  # a list of item ids: skip it
            pos += 2 + struct.unpack("<H", data[pos : pos + 2])[0]
        if flags & 0x02:  # LinkInfo
            target = _local_base_path(data, pos)
            pos += struct.unpack("<I", data[pos : pos + 4])[0]
        unicode = bool(flags & 0x80)
        fields: dict[str, str] = {}
        for bit, name in _STRING_FIELDS:
            if not flags & bit:
                continue
            (count,) = struct.unpack("<H", data[pos : pos + 2])
            pos += 2
            size = min(count * (2 if unicode else 1), 65_536)
            raw = data[pos : pos + size]
            pos += size
            fields[name] = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
    except (struct.error, IndexError):
        return _done(data, "lnk", st)

    args = fields.get("args", "")
    program = (target or fields.get("relative", "")).replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if args:
        contentscan._scan_text(args, st, 0)  # noqa: SLF001
        if st.obfuscation >= 10:
            st.add("string_obfuscation", st.obfuscation)
    if program in _INTERPRETERS and args.strip():
        st.add("lnk_interpreter")
    if len(args) > 260 or _PADDING.search(args):
        st.add("lnk_hidden_args")
    if args.strip() and _ICON_LURES.search(fields.get("icon", "")):
        st.add("lnk_icon_lure")
    return _done(data, "lnk", st)


def _done(data: bytes, family: str, st: Any) -> dict[str, Any]:
    out: dict[str, Any] = contentscan.result(data, family, st)
    return out
