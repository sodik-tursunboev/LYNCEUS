"""The sandbox does what ADR-008 claims, shown by a hostile probe running inside it.

Every isolation claim has a positive control: the same action succeeds outside the sandbox, or on
something the sandbox may touch, so a "denied" result cannot come from a broken test.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from core import sandbox
from core.sandbox import Limits, SandboxUnavailable, frame

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the sandbox is Windows-only")
PROBE = Path(__file__).parent / "probe.py"
ROOT = Path(__file__).parents[2]
FAST = Limits(memory_mb=256, cpu_seconds=5, wall_seconds=20)


@pytest.fixture(scope="session", autouse=True)
def built() -> None:
    if not sandbox.available():  # fail loudly: skipping would hide a missing security control
        pytest.fail("sandbox not built: run `python tasks.py sandbox`", pytrace=False)
    shutil.copy2(PROBE, sandbox.APP / "probe.py")


def probe(limits: Limits = FAST, **cmd: Any) -> dict[str, Any]:
    r = sandbox.run("probe.py", json.dumps(cmd).encode(), limits)
    assert r.ok, (cmd, r.reason, r.exit_code)
    out: dict[str, Any] = json.loads(r.output)
    return out


# ---- the worker itself ------------------------------------------------------------------------


def test_worker_round_trip() -> None:
    body = b"hello sandbox"
    r = sandbox.run("main.py", frame({"op": "ping"}, body))
    assert r.ok and r.reason == "ok" and r.exit_code == 0
    answer = json.loads(r.output)
    import hashlib

    assert answer["sha256"] == hashlib.sha256(body).hexdigest() and answer["bytes"] == len(body)


def test_unknown_operation_is_an_answer_not_a_crash() -> None:
    r = sandbox.run("main.py", frame({"op": "nope"}))
    assert r.ok and json.loads(r.output) == {"error": "unknown_op"}


def test_malformed_input_crashes_the_worker_not_the_caller() -> None:
    r = sandbox.run("main.py", b"\xff\xff\xff\xffnot a frame")
    assert not r.ok and r.reason == "crashed" and r.output == b""


def test_a_large_input_goes_through() -> None:
    body = os.urandom(8 * 1024 * 1024)
    r = sandbox.run("main.py", frame({"op": "ping"}, body))
    assert r.ok and json.loads(r.output)["bytes"] == len(body)


def test_parallel_sandboxes_are_independent() -> None:
    results: list[bool] = []

    def one() -> None:
        results.append(sandbox.run("main.py", frame({"op": "ping"}, b"x")).ok)

    threads = [threading.Thread(target=one) for _ in range(4)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert results == [True] * 4


# ---- identity and environment -----------------------------------------------------------------


def test_the_worker_runs_in_an_appcontainer() -> None:
    from core.sandbox._win32 import advapi32  # noqa: F401  (import proves the module loads)

    assert probe(cmd="token")["appcontainer"] is True


def test_the_worker_sees_no_user_paths_or_secrets() -> None:
    seen = probe(cmd="env")
    blob = json.dumps(seen["env"])  # the environment, not the working directory (below)
    for private in (os.environ["USERNAME"], os.environ["USERPROFILE"], "MIRAGE_", "API_TOKEN"):
        assert private.lower() not in blob.lower(), private
    assert set(seen["env"]) >= {"LOCALAPPDATA", "SYSTEMROOT"}
    # The worker's own folder is the one path it must know; a clone under the user profile puts the
    # user name in that path, which is not a leak of anything the worker was not given.
    assert Path(seen["cwd"]).resolve() == sandbox.APP.resolve()


# ---- files: denied outside the grant, with controls -------------------------------------------


def test_cannot_read_user_files(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("private", encoding="utf-8")
    assert secret.read_bytes() == b"private"  # control: outside the sandbox it is readable
    assert probe(cmd="read", path=str(secret))["done"] is False


def test_cannot_read_the_project_or_its_secrets() -> None:
    assert (ROOT / "pyproject.toml").read_bytes()  # control
    assert probe(cmd="read", path=str(ROOT / "pyproject.toml"))["done"] is False
    env_file = ROOT / ".env"
    if env_file.exists():
        assert probe(cmd="read", path=str(env_file))["done"] is False


def test_cannot_list_the_users_folders() -> None:
    assert os.listdir(Path.home())  # control
    assert probe(cmd="list", path=str(Path.home()))["done"] is False


def test_can_read_what_it_was_granted() -> None:
    # Control for the denials above: the probe really can read, just not your files.
    assert probe(cmd="read", path=str(sandbox.APP / "probe.py"))["done"] is True


def test_cannot_write_anywhere(tmp_path: Path) -> None:
    for target in (tmp_path / "w.txt", sandbox.APP / "w.txt", sandbox.RUNTIME / "w.txt"):
        assert probe(cmd="write", path=str(target))["done"] is False
        assert not target.exists()
    mine = tmp_path / "control.txt"
    mine.write_bytes(b"x")  # control: the parent can write there
    assert mine.exists()


# ---- network: denied, with a control ----------------------------------------------------------


def test_cannot_connect_even_to_loopback() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass  # control: the parent connects to the very same listener
        assert probe(cmd="net", host="127.0.0.1", port=port)["done"] is False


# ---- processes --------------------------------------------------------------------------------


def test_cannot_start_other_programs() -> None:
    assert probe(cmd="spawn")["done"] is False


# ---- limits: each one stops the worker and leaves the caller alive ----------------------------


def test_memory_is_capped() -> None:
    limits = Limits(memory_mb=200, cpu_seconds=10, wall_seconds=30)
    r = sandbox.run("probe.py", json.dumps({"cmd": "alloc", "mb": 3000}).encode(), limits)
    assert r.peak_memory_mb <= 200 * 1.1  # however it ended, it never held more
    if r.ok:  # the interpreter raised MemoryError and answered
        assert json.loads(r.output)["allocated_mb"] < 200
    else:
        assert r.reason in ("memory_limit", "crashed")


def test_a_cpu_spin_is_stopped_by_the_cpu_limit() -> None:
    limits = Limits(memory_mb=256, cpu_seconds=1, wall_seconds=30)
    r = sandbox.run("probe.py", json.dumps({"cmd": "spin"}).encode(), limits)
    assert not r.ok and r.reason == "cpu_limit"
    assert r.wall_seconds < 15


def test_a_stuck_worker_is_stopped_by_the_deadline_and_does_not_outlive_it() -> None:
    limits = Limits(memory_mb=256, cpu_seconds=10, wall_seconds=1.5)
    r = sandbox.run("probe.py", json.dumps({"cmd": "sleep", "seconds": 60}).encode(), limits)
    assert not r.ok and r.reason == "timeout" and r.wall_seconds < 15
    from core.sandbox._win32 import process_exited

    assert process_exited(r.pid)


def _sandbox_pids() -> set[int]:
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
        "Where-Object { $_.ExecutablePath -like '*\\.sandbox\\runtime\\python.exe' } | "
        "ForEach-Object { $_.ProcessId }"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=90, check=False,
    ).stdout  # fmt: skip
    return {int(x) for x in out.split()}


def _wait_for(condition: Callable[[], bool], seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.5)
    return condition()


def test_the_worker_dies_with_its_parent() -> None:
    before = _sandbox_pids()
    code = (
        "import json; from core import sandbox; "
        "sandbox.run('probe.py', json.dumps({'cmd': 'sleep', 'seconds': 120}).encode(), "
        "sandbox.Limits(wall_seconds=300))"
    )
    parent = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT)  # noqa: S603
    try:
        assert _wait_for(lambda: bool(_sandbox_pids() - before), 30), "the worker never started"
        parent.kill()  # a crash of the caller: no cleanup code gets to run
        assert _wait_for(lambda: not (_sandbox_pids() - before), 20), (
            "the worker outlived its parent"
        )
    finally:
        parent.kill()
        for pid in _sandbox_pids() - before:  # never leave a stray behind, whatever happened
            cmd = ["taskkill", "/F", "/PID", str(pid)]
            subprocess.run(cmd, capture_output=True, check=False)


def test_an_output_flood_is_capped() -> None:
    limits = Limits(memory_mb=256, cpu_seconds=10, wall_seconds=30, max_output_bytes=1024 * 1024)
    r = sandbox.run("probe.py", json.dumps({"cmd": "flood", "mb": 200}).encode(), limits)
    assert not r.ok and r.reason == "output_limit"
    assert len(r.output) <= 1024 * 1024 + 65536 + 65536  # cap plus at most a read or two in flight


# ---- the API refuses what it should -----------------------------------------------------------


def test_input_over_the_cap_is_refused_before_anything_starts() -> None:
    with pytest.raises(ValueError, match="limit"):
        sandbox.run("main.py", b"x" * (sandbox.MAX_INPUT_BYTES + 1))


@pytest.mark.parametrize(
    "script", ["..\\main.py", "../main.py", "sub\\main.py", "main.exe", "C:\\Windows\\x.py", ""]
)
def test_only_plain_script_names_inside_the_app_folder(script: str) -> None:
    with pytest.raises(ValueError, match="script"):
        sandbox.run(script)


def test_a_missing_sandbox_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sandbox, "RUNTIME", tmp_path / "nowhere")
    with pytest.raises(SandboxUnavailable, match="not built"):
        sandbox.run("main.py", frame({"op": "ping"}))


def test_a_container_that_will_not_start_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox, "CONTAINER", "mirage.notregistered")
    with pytest.raises(SandboxUnavailable, match="would not start"):
        sandbox.run("main.py", frame({"op": "ping"}))


def test_a_script_that_does_not_exist_is_a_crash_not_a_fallback() -> None:
    r = sandbox.run("missing.py", b"")
    assert not r.ok and r.reason == "crashed"
