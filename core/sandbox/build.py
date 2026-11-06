"""Build .sandbox/: a private interpreter copy and the worker code (python tasks.py sandbox).

Only this folder is made readable to the sandbox's AppContainer SID, and read-only. The project
root, which holds .env, is never granted.

Windows will not start a process in an AppContainer whose profile is not registered, so building
registers one per user (a registry key and %LOCALAPPDATA%\\Packages\\mirage.parser). Undo it with
`python -m core.sandbox.build --remove`, which deletes the profile and the .sandbox folder.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from core.sandbox import APP, CONTAINER, RUNTIME, SANDBOX_DIR, SandboxUnavailable

GUEST = Path(__file__).parent / "guest"
REQUIREMENTS = Path(__file__).parents[2] / "requirements-sandbox.txt"
_SKIP = {  # parts of the standard library the worker never needs
    "site-packages", "test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip",
    "__pycache__", "venv", "lib2to3",
}  # fmt: skip


def _copy_lib(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=lambda _d, names: [n for n in names if n in _SKIP])
    (dst / "site-packages").mkdir()


def _install_parsers() -> None:
    """The PDF and image libraries, from hash-pinned wheels only, into the sandbox's own Lib."""
    done = subprocess.run(  # noqa: S603
        [
            sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
            "--target", str(RUNTIME / "Lib" / "site-packages"),
            "--require-hashes", "--only-binary=:all:", "--no-deps",
            "-r", str(REQUIREMENTS),
        ],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if done.returncode != 0:
        raise SandboxUnavailable(f"could not install the parser libraries: {done.stderr.strip()}")
    for video_plugin in (RUNTIME / "Lib" / "site-packages" / "cv2").glob("opencv_videoio_ffmpeg*"):
        video_plugin.unlink()  # 29 MB of media decoders that QR detection never calls


def _drop_profile_grant(sid: str) -> None:
    """Windows gives the container full control of its own profile folder (Packages\\<name>\\AC).
    The worker needs nothing there, and a compromised worker could leave state in it for the next
    message's worker, with no quota. Take the grant away: the container then can write nowhere."""
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return
    profile = Path(local) / "Packages" / CONTAINER / "AC"
    if profile.exists():
        subprocess.run(  # noqa: S603
            ["icacls", str(profile), "/remove:g", f"*{sid}", "/T", "/C", "/Q"],  # noqa: S607
            capture_output=True, text=True, check=False,
        )  # fmt: skip


def build() -> None:
    if sys.platform != "win32":
        raise SandboxUnavailable("the sandbox is implemented for Windows only (ADR-008)")
    base = Path(sys.base_prefix)
    if SANDBOX_DIR.exists():
        shutil.rmtree(SANDBOX_DIR)
    RUNTIME.mkdir(parents=True)
    for pattern in ("python.exe", "python3*.dll", "vcruntime*.dll"):
        for f in base.glob(pattern):
            shutil.copy2(f, RUNTIME / f.name)
    shutil.copytree(base / "DLLs", RUNTIME / "DLLs")
    _copy_lib(base / "Lib", RUNTIME / "Lib")
    shutil.copytree(GUEST, APP, ignore=shutil.ignore_patterns("__pycache__"))
    _install_parsers()
    register()


def register() -> None:
    """Register this user's container profile and give it read-only access to an already built
    .sandbox. The installer ships the sandbox built; this is the only step it needs on the user's
    machine (the profile and the folder permission are per user and per place)."""
    if sys.platform != "win32":
        raise SandboxUnavailable("the sandbox is implemented for Windows only (ADR-008)")
    from core.sandbox import _win32

    if not (RUNTIME / "python.exe").exists() or not APP.exists():
        raise SandboxUnavailable(f"{SANDBOX_DIR} is not built: run python tasks.py sandbox")
    sid = _win32.register_container(CONTAINER)
    done = subprocess.run(  # noqa: S603
        ["icacls", str(SANDBOX_DIR), "/grant", f"*{sid}:(OI)(CI)(RX)", "/T", "/C", "/Q"],  # noqa: S607
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if done.returncode != 0:
        raise SandboxUnavailable(f"could not grant the sandbox read access: {done.stderr.strip()}")
    _drop_profile_grant(sid)
    print(f"sandbox ready: {SANDBOX_DIR} (container {CONTAINER}, read-only grant to {sid})")


def remove() -> None:
    if sys.platform != "win32":
        return
    from core.sandbox import _win32

    _win32.remove_container(CONTAINER)
    if SANDBOX_DIR.exists():
        shutil.rmtree(SANDBOX_DIR)
    print(f"removed the {CONTAINER} profile and {SANDBOX_DIR}")


if __name__ == "__main__":
    if "--remove" in sys.argv[1:]:
        remove()
    elif "--register" in sys.argv[1:]:
        register()
    else:
        build()
