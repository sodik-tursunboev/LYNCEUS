"""Windows executables, read by the published header layout. Standard library only.

Not a disassembler and not an antivirus: it reports cheap, hard-to-fake structure facts (packed
sections, memory that is both writable and executable, a large hidden tail, imports typical of
injecting into other processes or of downloading and starting a program) so the host can weigh them
next to everything else. Nothing is run or loaded.
"""

import re
import struct
from typing import Any

import contentscan
from limits import MAX_CONTENT_BYTES

_INJECT = (
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"NtUnmapViewOfSection",
    b"SetThreadContext", b"QueueUserAPC", b"NtCreateThreadEx", b"RtlCreateUserThread",
    b"NtWriteVirtualMemory",
)  # fmt: skip
_DOWNLOAD = (
    b"URLDownloadToFile", b"InternetOpenUrl", b"InternetReadFile", b"WinHttpOpen",
    b"WinHttpReadData", b"HttpSendRequest",
)  # fmt: skip
_RUN = (b"ShellExecute", b"WinExec", b"CreateProcess")
_URL_BYTES = re.compile(rb"https?://[ -~]{4,300}", re.IGNORECASE)
_EXEC, _WRITE = 0x20000000, 0x80000000


def scan_pe(data: bytes) -> dict[str, Any]:
    st = contentscan._State()  # noqa: SLF001
    sample = data[: MAX_CONTENT_BYTES * 2]
    try:
        (lfanew,) = struct.unpack("<I", data[0x3C:0x40])
        if lfanew > len(data) - 24 or data[lfanew : lfanew + 4] != b"PE\x00\x00":
            return _done(data, "pe", st)  # an old DOS program or a damaged header
        count, _stamp, _sym, _nsym, opt_size = struct.unpack(
            "<HIIIH", data[lfanew + 6 : lfanew + 22]
        )
        opt = lfanew + 24
        (magic,) = struct.unpack("<H", data[opt : opt + 2])
        dirs = opt + (0x70 if magic == 0x20B else 0x60)
        (import_rva, import_size) = struct.unpack("<II", data[dirs + 8 : dirs + 16])
        table = opt + opt_size
        end_of_sections = 0
        packed = rwx = False
        for i in range(min(count, 96)):
            at = table + 40 * i
            (_vs, _va, raw_size, raw_ptr) = struct.unpack("<IIII", data[at + 8 : at + 24])
            (flags,) = struct.unpack("<I", data[at + 36 : at + 40])
            end_of_sections = max(end_of_sections, raw_ptr + raw_size)
            if flags & _EXEC and flags & _WRITE:
                rwx = True
            body = data[raw_ptr : raw_ptr + min(raw_size, MAX_CONTENT_BYTES)]
            big_enough = (flags & _EXEC or raw_size >= 65_536) and len(body) >= 4096
            if big_enough and contentscan.entropy(body) >= 7.2:
                packed = True
        overall = contentscan.entropy(data)
        if packed or (import_size == 0 and overall >= 7.0):
            st.add("pe_packed")
        if rwx:
            st.add("pe_rwx")
        overlay = len(data) - end_of_sections
        if end_of_sections and overlay > max(65_536, len(data) // 2):
            st.add("pe_overlay")
    except (struct.error, IndexError):
        pass  # a truncated or hostile header: report what was learned so far
    if sum(api in sample for api in _INJECT) >= 3:
        st.add("pe_injection_apis")
    if any(api in sample for api in _DOWNLOAD) and any(api in sample for api in _RUN):
        st.add("pe_downloader_apis")
    for m in _URL_BYTES.finditer(sample):
        st.take_urls(m.group(0).decode("ascii", "replace"))
    return _done(data, "pe", st)


def _done(data: bytes, family: str, st: Any) -> dict[str, Any]:
    out: dict[str, Any] = contentscan.result(data, family, st)
    return out
