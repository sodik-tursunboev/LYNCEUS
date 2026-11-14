"""Run the detonator (D1): one throwaway container per page, behind the egress proxy.

Layout, created on first use and checked every time:
  lynceus-dn-inner  an --internal Docker network: no route to anywhere
  lynceus-dn-outer  an ordinary bridge network
  lynceus-egress    the proxy container, on both; the only thing a browser container can reach
Each page gets a fresh container on the inner network only: non-root, Chromium's sandbox on under
Playwright's seccomp profile, no capabilities, read-only, memory/CPU/process limits, killed at
WALL_SECONDS. Nothing is mounted from this machine. The docker CLI is called with argument lists,
never a shell.
"""

import json
import logging
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from pydantic import ValidationError

from core.detonate.models import PageReport

log = logging.getLogger(__name__)
IMAGE = "lynceus-detonator:1.1.0"
INNER, OUTER, EGRESS = "lynceus-dn-inner", "lynceus-dn-outer", "lynceus-egress"
PROXY = f"http://{EGRESS}:3128"
HERE = Path(__file__).resolve().parents[2] / "infra" / "detonator"
SECCOMP = HERE / "seccomp_profile.json"
WALL_SECONDS = 32
MAX_OUTPUT = 4 * 1024 * 1024
MAX_PARALLEL = 3
RECHECK_SECONDS = 60  # how long a successful setup check is trusted
_slots = threading.BoundedSemaphore(MAX_PARALLEL)
_ready = threading.Lock()
_checked_at: list[float] = []  # monotonic time of the last successful check

HARDENING = [
    "--user", "pwuser", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--log-driver", "none",
]  # fmt: skip


class Unavailable(Exception):
    """Detonation cannot run here (no Docker, engine stopped, image not built, busy)."""


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Unavailable("docker_unresponsive") from e


def ensure_ready() -> None:
    """Docker is up, the image exists, the two networks and the proxy are in place. A success is
    trusted for RECHECK_SECONDS (each check is five docker calls); a failure is never cached."""
    with _ready:
        if _checked_at and time.monotonic() - _checked_at[0] < RECHECK_SECONDS:
            return
        _checked_at.clear()
        _check()
        _checked_at.append(time.monotonic())


def _check() -> None:
    if shutil.which("docker") is None:
        raise Unavailable("docker_missing")
    if _docker("version", "--format", "{{.Server.Version}}", timeout=20).returncode != 0:
        raise Unavailable("docker_stopped")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        raise Unavailable("image_missing")  # python tasks.py detonator
    for net, internal in ((INNER, True), (OUTER, False)):
        if _docker("network", "inspect", net).returncode != 0:
            made = _docker("network", "create", *(["--internal"] if internal else []), net)
            if made.returncode != 0:
                raise Unavailable("network")
    running = _docker("container", "inspect", "-f", "{{.State.Running}}", EGRESS)
    if running.stdout.strip() == "true":
        return
    _docker("rm", "-f", EGRESS)
    started = _docker(
        "run", "-d", "--name", EGRESS, "--network", OUTER, *HARDENING,
        "--memory", "256m", "--pids-limit", "128",
        "--entrypoint", "/usr/bin/python3", IMAGE, "-I", "/opt/detonator/egress.py",
    )  # fmt: skip
    if started.returncode != 0 or _docker("network", "connect", INNER, EGRESS).returncode:
        raise Unavailable("egress")


# Chromium's sandbox chroots itself inside a new user namespace. Docker's seccomp profile allows the
# chroot call only to a container that holds SYS_CHROOT, so the browser containers get that one
# capability back. The browser runs as pwuser, so it has no effective capabilities on the container.
BROWSER = [*HARDENING, "--cap-add", "SYS_CHROOT", "--security-opt", f"seccomp={SECCOMP}"]


def command(name: str) -> list[str]:
    return [
        "docker", "run", "--rm", "-i", "--name", name, "--network", INNER, *BROWSER,
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--memory", "1g", "--memory-swap", "1g", "--cpus", "1.5", "--pids-limit", "512",
        "--shm-size", "1g", "--init", IMAGE,
    ]  # fmt: skip


def _run(name: str, request: bytes) -> PageReport:
    proc = subprocess.Popen(  # noqa: S603  (fixed argument list, no shell)
        command(name), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    out = bytearray()

    def pump() -> None:
        if proc.stdin is None or proc.stdout is None:
            return
        try:
            proc.stdin.write(request)
            proc.stdin.close()
            while len(out) <= MAX_OUTPUT and (chunk := proc.stdout.read(65536)):
                out.extend(chunk)
        except OSError:
            pass

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    t.join(WALL_SECONDS)
    if t.is_alive() or len(out) > MAX_OUTPUT:
        _docker("kill", name, timeout=15)
        proc.kill()
        return PageReport(status="error", error="timeout" if t.is_alive() else "output_limit")
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
    try:
        return PageReport.model_validate_json(bytes(out))
    except ValidationError:
        log.warning("the detonator's reply did not match the schema (%d bytes)", len(out))
        return PageReport(status="error", error="bad_reply")


def detonate(url: str) -> PageReport:
    """Open `url` in a fresh container and describe the page. Raises Unavailable when it cannot
    run at all; a page that fails to load comes back as a report with status dead/error."""
    ensure_ready()
    if not _slots.acquire(timeout=90):
        raise Unavailable("busy")
    try:
        name = f"lynceus-dn-{uuid.uuid4().hex[:12]}"
        return _run(name, json.dumps({"url": url, "proxy": PROXY}).encode())
    finally:
        _slots.release()
