"""Win32 plumbing for the parser sandbox (ADR-008, option B). Windows only; import it lazily.

Two layers, and what each is for:
- An AppContainer token with no capabilities. That is what denies network access and every file
  that has not been granted to the container's SID. The Job Object does not do this.
- A Job Object: hard memory and CPU-time limits, one process only, no UI access, and the whole
  tree dies when the job handle closes (so also when this process dies).
The parent adds a wall-clock deadline and an output cap, and kills the job when either is hit.
"""

import ctypes
import msvcrt
import os
import threading
import time
from collections.abc import Callable
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_int64,
    c_size_t,
    c_uint32,
    c_uint64,
    c_void_p,
    c_wchar_p,
    sizeof,
    wintypes,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Any

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

HANDLE = c_void_p
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x1
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
JOB_BASIC_ACCOUNTING = 1
JOB_BASIC_UI_RESTRICTIONS = 4
JOB_EXTENDED_LIMIT = 9
LIMIT_JOB_TIME = 0x4
LIMIT_ACTIVE_PROCESS = 0x8
LIMIT_PROCESS_MEMORY = 0x100
LIMIT_JOB_MEMORY = 0x200
LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
LIMIT_KILL_ON_JOB_CLOSE = 0x2000
UI_LIMIT_ALL = 0xFF  # handles, clipboard, system parameters, display, atoms, desktop, exit windows
WAIT_TIMEOUT = 0x102
WAIT_OBJECT_0 = 0
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ_WRITE = 0x3
OPEN_EXISTING = 3
ERROR_INSUFFICIENT_BUFFER = 122


class SecurityAttributes(Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class IoCounters(Structure):
    _fields_ = [
        (n, c_uint64)
        for n in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class JobBasicLimit(Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", c_int64),
        ("PerJobUserTimeLimit", c_int64),
        ("LimitFlags", c_uint32),
        ("MinimumWorkingSetSize", c_size_t),
        ("MaximumWorkingSetSize", c_size_t),
        ("ActiveProcessLimit", c_uint32),
        ("Affinity", c_size_t),
        ("PriorityClass", c_uint32),
        ("SchedulingClass", c_uint32),
    ]


class JobExtendedLimit(Structure):
    _fields_ = [
        ("BasicLimitInformation", JobBasicLimit),
        ("IoInfo", IoCounters),
        ("ProcessMemoryLimit", c_size_t),
        ("JobMemoryLimit", c_size_t),
        ("PeakProcessMemoryUsed", c_size_t),
        ("PeakJobMemoryUsed", c_size_t),
    ]


class JobBasicAccounting(Structure):
    _fields_ = [
        ("TotalUserTime", c_int64),
        ("TotalKernelTime", c_int64),
        ("ThisPeriodTotalUserTime", c_int64),
        ("ThisPeriodTotalKernelTime", c_int64),
        ("TotalPageFaultCount", c_uint32),
        ("TotalProcesses", c_uint32),
        ("ActiveProcesses", c_uint32),
        ("TotalTerminatedProcesses", c_uint32),
    ]


class JobUiRestrictions(Structure):
    _fields_ = [("UIRestrictionClass", c_uint32)]


class SecurityCapabilities(Structure):
    _fields_ = [
        ("AppContainerSid", c_void_p),
        ("Capabilities", c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class StartupInfoW(Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", c_wchar_p),
        ("lpDesktop", c_wchar_p),
        ("lpTitle", c_wchar_p),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", c_void_p),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class StartupInfoExW(Structure):
    _fields_ = [("StartupInfo", StartupInfoW), ("lpAttributeList", c_void_p)]


class ProcessInformation(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _bind() -> None:
    k, u, a = kernel32, userenv, advapi32
    sig: list[tuple[Any, Any, list[Any]]] = [
        (k.CreateJobObjectW, HANDLE, [c_void_p, c_wchar_p]),
        (
            k.SetInformationJobObject,
            wintypes.BOOL,
            [HANDLE, ctypes.c_int, c_void_p, wintypes.DWORD],
        ),
        (
            k.QueryInformationJobObject,
            wintypes.BOOL,
            [HANDLE, ctypes.c_int, c_void_p, wintypes.DWORD, c_void_p],
        ),
        (k.AssignProcessToJobObject, wintypes.BOOL, [HANDLE, HANDLE]),
        (k.TerminateJobObject, wintypes.BOOL, [HANDLE, wintypes.UINT]),
        (k.CreatePipe, wintypes.BOOL, [POINTER(HANDLE), POINTER(HANDLE), c_void_p, wintypes.DWORD]),
        (k.SetHandleInformation, wintypes.BOOL, [HANDLE, wintypes.DWORD, wintypes.DWORD]),
        (
            k.CreateFileW,
            HANDLE,
            [
                c_wchar_p,
                wintypes.DWORD,
                wintypes.DWORD,
                c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                HANDLE,
            ],
        ),
        (
            k.InitializeProcThreadAttributeList,
            wintypes.BOOL,
            [c_void_p, wintypes.DWORD, wintypes.DWORD, POINTER(c_size_t)],
        ),
        (
            k.UpdateProcThreadAttribute,
            wintypes.BOOL,
            [c_void_p, wintypes.DWORD, c_size_t, c_void_p, c_size_t, c_void_p, c_void_p],
        ),
        (k.DeleteProcThreadAttributeList, None, [c_void_p]),
        (
            k.CreateProcessW,
            wintypes.BOOL,
            [
                c_wchar_p,
                c_wchar_p,
                c_void_p,
                c_void_p,
                wintypes.BOOL,
                wintypes.DWORD,
                c_void_p,
                c_wchar_p,
                c_void_p,
                c_void_p,
            ],
        ),
        (k.ResumeThread, wintypes.DWORD, [HANDLE]),
        (k.WaitForSingleObject, wintypes.DWORD, [HANDLE, wintypes.DWORD]),
        (k.GetExitCodeProcess, wintypes.BOOL, [HANDLE, POINTER(wintypes.DWORD)]),
        (k.CloseHandle, wintypes.BOOL, [HANDLE]),
        (k.OpenProcess, HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
        (
            u.DeriveAppContainerSidFromAppContainerName,
            ctypes.c_long,
            [c_wchar_p, POINTER(c_void_p)],
        ),
        (
            u.CreateAppContainerProfile,
            ctypes.c_long,
            [c_wchar_p, c_wchar_p, c_wchar_p, c_void_p, wintypes.DWORD, POINTER(c_void_p)],
        ),
        (u.DeleteAppContainerProfile, ctypes.c_long, [c_wchar_p]),
        (a.ConvertSidToStringSidW, wintypes.BOOL, [c_void_p, POINTER(c_wchar_p)]),
        (a.FreeSid, c_void_p, [c_void_p]),
        (k.LocalFree, c_void_p, [c_void_p]),
    ]
    for fn, res, args in sig:
        fn.restype, fn.argtypes = res, args


_bind()


class Win32Error(OSError):
    pass


def _check(ok: object, what: str) -> None:
    if not ok:
        code = ctypes.get_last_error()
        raise Win32Error(code, f"{what} failed (Win32 error {code})")


HR_ALREADY_EXISTS = 0x800700B7
HR_NOT_FOUND = 0x80070490


def register_container(name: str) -> str:
    """Register the per-user AppContainer profile Windows requires, and return its SID.

    Side effects outside the project: a key under HKCU\\Software\\Classes\\Local Settings\\...\\
    AppContainer and a folder %LOCALAPPDATA%\\Packages\\<name>. `remove_container` undoes both.
    """
    sid = c_void_p()
    hr = (
        userenv.CreateAppContainerProfile(
            name,
            "Lynceus parser sandbox",
            "Runs untrusted parsers with no network or file access",
            None,
            0,
            byref(sid),
        )
        & 0xFFFFFFFF
    )
    if hr == 0:
        advapi32.FreeSid(sid)
    elif hr != HR_ALREADY_EXISTS:
        raise Win32Error(hr, f"CreateAppContainerProfile failed (HRESULT {hr:#x})")
    return sid_string(name)


def remove_container(name: str) -> None:
    hr = userenv.DeleteAppContainerProfile(name) & 0xFFFFFFFF
    if hr not in (0, HR_NOT_FOUND):
        raise Win32Error(hr, f"DeleteAppContainerProfile failed (HRESULT {hr:#x})")


def container_sid(name: str) -> tuple[c_void_p, str]:
    """The AppContainer SID derived from a name (the profile must be registered to launch)."""
    sid = c_void_p()
    hr = userenv.DeriveAppContainerSidFromAppContainerName(name, byref(sid))
    if hr != 0:
        raise Win32Error(hr, f"DeriveAppContainerSid failed (HRESULT {hr & 0xFFFFFFFF:#x})")
    text = c_wchar_p()
    _check(advapi32.ConvertSidToStringSidW(sid, byref(text)), "ConvertSidToStringSid")
    value = str(text.value)
    kernel32.LocalFree(text)
    return sid, value


def sid_string(name: str) -> str:
    sid, text = container_sid(name)
    advapi32.FreeSid(sid)
    return text


@dataclass(frozen=True)
class Limits:
    memory_mb: int = 512  # committed memory of the one process
    cpu_seconds: int = 10  # user CPU time of the job
    wall_seconds: float = 15.0  # includes interpreter start-up
    max_output_bytes: int = 4 * 1024 * 1024


@dataclass(frozen=True)
class Result:
    ok: bool
    output: bytes
    reason: str  # ok, timeout, cpu_limit, memory_limit, output_limit, crashed
    exit_code: int | None
    cpu_seconds: float
    peak_memory_mb: float
    wall_seconds: float
    pid: int


def _job(limits: Limits) -> int:
    job = int(kernel32.CreateJobObjectW(None, None) or 0)
    _check(job, "CreateJobObject")
    ext = JobExtendedLimit()
    ext.BasicLimitInformation.LimitFlags = (
        LIMIT_JOB_TIME
        | LIMIT_ACTIVE_PROCESS
        | LIMIT_PROCESS_MEMORY
        | LIMIT_JOB_MEMORY
        | LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | LIMIT_KILL_ON_JOB_CLOSE
    )
    ext.BasicLimitInformation.PerJobUserTimeLimit = limits.cpu_seconds * 10_000_000  # 100 ns units
    ext.BasicLimitInformation.ActiveProcessLimit = 1
    ext.ProcessMemoryLimit = ext.JobMemoryLimit = limits.memory_mb * 1024 * 1024
    _check(
        kernel32.SetInformationJobObject(job, JOB_EXTENDED_LIMIT, byref(ext), sizeof(ext)),
        "SetInformationJobObject(limits)",
    )
    ui = JobUiRestrictions(UI_LIMIT_ALL)
    _check(
        kernel32.SetInformationJobObject(job, JOB_BASIC_UI_RESTRICTIONS, byref(ui), sizeof(ui)),
        "SetInformationJobObject(ui)",
    )
    return job


def _pipe() -> tuple[int, int]:
    sa = SecurityAttributes(sizeof(SecurityAttributes), None, True)
    r, w = HANDLE(), HANDLE()
    _check(kernel32.CreatePipe(byref(r), byref(w), byref(sa), 0), "CreatePipe")
    return int(r.value or 0), int(w.value or 0)


def _no_inherit(handle: int) -> None:
    _check(kernel32.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0), "SetHandleInformation")


def _environment(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    block = "".join(f"{k}={v}\0" for k, v in sorted(env.items())) + "\0"
    return ctypes.create_unicode_buffer(block, len(block))


def _usage(job: int) -> tuple[float, float]:
    acct, ext = JobBasicAccounting(), JobExtendedLimit()
    kernel32.QueryInformationJobObject(job, JOB_BASIC_ACCOUNTING, byref(acct), sizeof(acct), None)
    kernel32.QueryInformationJobObject(job, JOB_EXTENDED_LIMIT, byref(ext), sizeof(ext), None)
    return acct.TotalUserTime / 1e7, ext.PeakProcessMemoryUsed / (1024 * 1024)


def _pump_in(fd: int, data: bytes) -> None:
    try:
        with os.fdopen(fd, "wb", buffering=0) as f:
            view = memoryview(data)
            while view:
                view = view[f.write(view[:65536]) :]
    except OSError:
        pass  # the worker exited or was killed before reading everything


class _Reader(threading.Thread):
    def __init__(self, fd: int, cap: int, on_overflow: Callable[[], object]) -> None:
        super().__init__(daemon=True)
        self.fd, self.cap, self.on_overflow = fd, cap, on_overflow
        self.data, self.overflowed = bytearray(), False

    def run(self) -> None:
        try:
            with os.fdopen(self.fd, "rb", buffering=0) as f:
                while chunk := f.read(65536):
                    self.data += chunk
                    if len(self.data) > self.cap:
                        self.overflowed = True
                        self.on_overflow()
                        return
        except OSError:
            pass


def run(
    app: str,
    args: list[str],
    stdin: bytes,
    limits: Limits,
    container: str,
    cwd: Path,
    env: dict[str, str],
) -> Result:
    sid, _ = container_sid(container)
    job = _job(limits)
    in_r, in_w = _pipe()
    out_r, out_w = _pipe()
    err = kernel32.CreateFileW(
        "NUL",
        GENERIC_WRITE,
        FILE_SHARE_READ_WRITE,
        byref(SecurityAttributes(sizeof(SecurityAttributes), None, True)),
        OPEN_EXISTING,
        0,
        None,
    )
    _check(err not in (None, ctypes.c_void_p(-1).value), "open NUL")
    _no_inherit(in_w)
    _no_inherit(out_r)
    attrs_ptr = None
    started = time.perf_counter()
    pi = ProcessInformation()
    try:
        size = c_size_t()
        kernel32.InitializeProcThreadAttributeList(None, 2, 0, byref(size))
        attrs = ctypes.create_string_buffer(size.value)
        attrs_ptr = ctypes.cast(attrs, c_void_p)
        _check(
            kernel32.InitializeProcThreadAttributeList(attrs_ptr, 2, 0, byref(size)),
            "InitializeProcThreadAttributeList",
        )
        caps = SecurityCapabilities(sid, None, 0, 0)
        _check(
            kernel32.UpdateProcThreadAttribute(
                attrs_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                byref(caps),
                sizeof(caps),
                None,
                None,
            ),
            "UpdateProcThreadAttribute(container)",
        )
        inherited = (HANDLE * 3)(in_r, out_w, err)
        _check(
            kernel32.UpdateProcThreadAttribute(
                attrs_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                byref(inherited),
                sizeof(inherited),
                None,
                None,
            ),
            "UpdateProcThreadAttribute(handles)",
        )

        si = StartupInfoExW()
        si.StartupInfo.cb = sizeof(StartupInfoExW)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = (
            in_r,
            out_w,
            err,
        )
        si.lpAttributeList = attrs_ptr
        cmdline = ctypes.create_unicode_buffer(subprocess_list2cmdline([app, *args]))
        _check(
            kernel32.CreateProcessW(
                app,
                cmdline,
                None,
                None,
                True,
                EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT,
                _environment(env),
                str(cwd),
                byref(si),
                byref(pi),
            ),
            "CreateProcess",
        )
        _check(kernel32.AssignProcessToJobObject(job, pi.hProcess), "AssignProcessToJobObject")
        _check(kernel32.ResumeThread(pi.hThread) != 0xFFFFFFFF, "ResumeThread")
    except BaseException:
        for h in (in_r, in_w, out_r, out_w, err):
            kernel32.CloseHandle(h)
        kernel32.CloseHandle(job)
        advapi32.FreeSid(sid)
        raise
    finally:
        if attrs_ptr is not None:
            kernel32.DeleteProcThreadAttributeList(attrs_ptr)
    # Our copies of the child's ends must close, or the reader never sees end-of-file.
    kernel32.CloseHandle(in_r)
    kernel32.CloseHandle(out_w)
    kernel32.CloseHandle(err)
    advapi32.FreeSid(sid)

    def kill() -> None:
        kernel32.TerminateJobObject(job, 1)

    reader = _Reader(msvcrt.open_osfhandle(out_r, os.O_RDONLY), limits.max_output_bytes, kill)
    writer = threading.Thread(
        target=_pump_in, args=(msvcrt.open_osfhandle(in_w, os.O_WRONLY), stdin), daemon=True
    )
    reader.start()
    writer.start()
    timed_out = (
        kernel32.WaitForSingleObject(pi.hProcess, int(limits.wall_seconds * 1000)) == WAIT_TIMEOUT
    )
    if timed_out:
        kill()
        kernel32.WaitForSingleObject(pi.hProcess, 5000)
    reader.join(5)
    writer.join(5)
    pid = int(pi.dwProcessId)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(pi.hProcess, byref(code))
    cpu, peak = _usage(job)
    kernel32.CloseHandle(pi.hThread)
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(job)  # KILL_ON_JOB_CLOSE: nothing outlives this call

    exit_code = int(code.value)
    if reader.overflowed:
        reason = "output_limit"
    elif timed_out:
        reason = "timeout"
    elif cpu >= limits.cpu_seconds * 0.98:
        reason = "cpu_limit"
    elif exit_code != 0 and peak >= limits.memory_mb * 0.9:
        reason = "memory_limit"
    elif exit_code != 0:
        reason = "crashed"
    else:
        reason = "ok"
    return Result(
        ok=reason == "ok",
        output=bytes(reader.data),
        reason=reason,
        exit_code=exit_code,
        cpu_seconds=cpu,
        peak_memory_mb=peak,
        wall_seconds=time.perf_counter() - started,
        pid=pid,
    )


def subprocess_list2cmdline(args: list[str]) -> str:
    import subprocess

    return subprocess.list2cmdline(args)


def process_exited(pid: int) -> bool:
    """True when no process with this id is running (used to prove nothing outlives a run)."""
    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        return True
    try:
        return bool(kernel32.WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
    finally:
        kernel32.CloseHandle(handle)
