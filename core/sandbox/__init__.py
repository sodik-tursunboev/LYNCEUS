"""Run hostile-input parsers in a sandboxed worker process (ADR-008). Fails closed.

`run()` returns a Result for every outcome of the worker, including being killed. It raises
`SandboxUnavailable` when the sandbox cannot be built or started: callers must report UNKNOWN or
ERROR with that reason and must never parse in-process instead.
"""

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SANDBOX_DIR = ROOT / ".sandbox"
RUNTIME = SANDBOX_DIR / "runtime"
APP = SANDBOX_DIR / "app"
CONTAINER = "mirage.parser"
MAX_INPUT_BYTES = 16 * 1024 * 1024
# The whole environment the worker sees. LOCALAPPDATA must exist for an AppContainer launch to
# succeed; a dummy value is enough (Windows derives TEMP from it). No real user path goes in.
_SAFE_ENV = {
    "SYSTEMROOT": "C:\\Windows",
    "LOCALAPPDATA": "C:\\sandbox",
    "PYTHONUTF8": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class SandboxUnavailable(RuntimeError):
    """The sandbox is missing or would not start. Never a reason to parse without it."""


@dataclass(frozen=True)
class Limits:
    memory_mb: int = 512
    cpu_seconds: int = 10
    wall_seconds: float = 15.0
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


def available() -> bool:
    return sys.platform == "win32" and (RUNTIME / "python.exe").exists() and APP.exists()


def run(script: str, stdin: bytes = b"", limits: Limits = Limits()) -> Result:  # noqa: B008
    """Run `.sandbox/app/<script>` in the sandbox with `stdin`; the worker answers on stdout."""
    if sys.platform != "win32":
        raise SandboxUnavailable("the sandbox is implemented for Windows only (ADR-008)")
    if len(stdin) > MAX_INPUT_BYTES:
        raise ValueError(f"input is over the {MAX_INPUT_BYTES}-byte limit")
    if Path(script).name != script or not script.endswith(".py"):
        raise ValueError("script must be a plain .py file name inside the sandbox app folder")
    if not available():
        raise SandboxUnavailable("sandbox not built: run python tasks.py sandbox")

    from core.sandbox import _win32

    try:
        r = _win32.run(
            str(RUNTIME / "python.exe"),
            ["-I", "-B", "-X", "utf8", str(APP / script)],
            stdin,
            _win32.Limits(
                limits.memory_mb, limits.cpu_seconds, limits.wall_seconds, limits.max_output_bytes
            ),
            CONTAINER,
            APP,
            dict(_SAFE_ENV),
        )
    except _win32.Win32Error as e:
        raise SandboxUnavailable(f"sandbox would not start: {e}") from e
    return Result(
        r.ok,
        r.output,
        r.reason,
        r.exit_code,
        r.cpu_seconds,
        r.peak_memory_mb,
        r.wall_seconds,
        r.pid,
    )


def frame(header: dict[str, object], body: bytes = b"") -> bytes:
    """The worker's request format: 4-byte header length, JSON header, raw body."""
    import json
    import struct

    head = json.dumps(header).encode("utf-8")
    return struct.pack(">I", len(head)) + head + body
