"""TEST ONLY. Runs inside the sandbox and tries things a hostile parser might try.

Copied into .sandbox/app by the test fixture; it is never part of the production worker. Standard
library only. Reads one JSON command from stdin and prints one JSON result.
"""

import ctypes
import json
import os
import socket
import subprocess
import sys
import time
from ctypes import wintypes


def token_is_appcontainer() -> bool | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x8, ctypes.byref(token)):
        return None
    value, size = wintypes.DWORD(), wintypes.DWORD()
    if not advapi32.GetTokenInformation(
        token, 29, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)
    ):
        return None  # 29 = TokenIsAppContainer
    return bool(value.value)


def read_some(path: str) -> int:
    with open(path, "rb") as f:
        return len(f.read(64))


def write_one(path: str) -> int:
    with open(path, "wb") as f:
        return f.write(b"x")


def attempt(fn) -> dict[str, object]:  # type: ignore[no-untyped-def]
    try:
        return {"done": True, "value": fn()}
    except BaseException as e:  # noqa: BLE001
        return {"done": False, "error": type(e).__name__}


def main() -> None:
    cmd = json.loads(sys.stdin.buffer.read())
    name = cmd["cmd"]
    if name == "token":
        out: dict[str, object] = {"appcontainer": token_is_appcontainer()}
    elif name == "env":
        out = {"env": dict(os.environ), "cwd": os.getcwd()}
    elif name == "read":
        out = attempt(lambda: read_some(cmd["path"]))
    elif name == "write":
        out = attempt(lambda: write_one(cmd["path"]))
    elif name == "list":
        out = attempt(lambda: len(os.listdir(cmd["path"])))
    elif name == "net":
        out = attempt(
            lambda: socket.create_connection((cmd["host"], cmd["port"]), timeout=3).close()
        )
    elif name == "spawn":
        out = attempt(
            lambda: (
                subprocess.run(
                    ["C:\\Windows\\System32\\cmd.exe", "/c", "echo", "x"],
                    capture_output=True,
                    timeout=5,
                ).returncode
            )
        )
    elif name == "alloc":
        held, mb = [], 0
        try:
            for _ in range(cmd["mb"]):
                held.append(bytearray(1024 * 1024))
                mb += 1
            out = {"allocated_mb": mb}
        except MemoryError:
            out = {"allocated_mb": mb, "memory_error": True}
    elif name == "spin":
        while True:
            pass
    elif name == "sleep":
        time.sleep(cmd["seconds"])
        out = {"slept": True}
    elif name == "flood":
        chunk = b"x" * 65536
        for _ in range(cmd["mb"] * 16):
            sys.stdout.buffer.write(chunk)
        out = {"flooded": True}
    else:
        out = {"error": "unknown_probe"}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()


main()
