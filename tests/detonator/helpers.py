"""Run the real detonator container for the tests (D1). Skips without Docker or the image."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core.detonate.models import PageReport
from core.detonate.runner import BROWSER, IMAGE

HERE = Path(__file__).parent


def docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        probe = subprocess.run(
            ["docker", "image", "inspect", IMAGE], capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


needs_docker = pytest.mark.skipif(
    not docker_ready(), reason="Docker or the detonator image missing"
)


def offline(page: str, timeout: float = 60) -> tuple[PageReport, str]:
    """Open a fixture page in the hardened container with no network at all."""
    cmd = [
        "docker", "run", "--rm", "--network", "none", *BROWSER,
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",  # noqa: S108  (the container's own tmpfs)
        "--memory", "1g", "--memory-swap", "1g", "--cpus", "1.5", "--pids-limit", "512",
        "--shm-size", "1g", "--init", "-v", f"{HERE}:/fixtures:ro",
        "--entrypoint", "/usr/bin/python3", IMAGE, "-I", "/fixtures/offline.py", page,
    ]  # fmt: skip
    done = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    out = done.stdout.decode("utf-8", "replace").strip().splitlines()
    raw = out[-1] if out else "{}"
    return PageReport.model_validate(json.loads(raw)), done.stderr.decode("utf-8", "replace")
