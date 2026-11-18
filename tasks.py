"""Task runner: python tasks.py <task> [extra args]. See ADR-003 (python tasks.py for the list)."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
PY = str(_VENV_PY) if _VENV_PY.exists() else sys.executable  # works without activating the venv
COMPOSE = "infra/docker-compose.yml"

TASKS: dict[str, list[list[str]]] = {
    "up": [["docker", "compose", "--env-file", ".env", "-f", COMPOSE, "up", "-d", "--wait"]],
    "test": [[PY, "-m", "pytest"]],
    "eval": [[PY, "-m", "eval"]],
    "lint": [
        [PY, "-m", "ruff", "check", "."],
        [PY, "-m", "ruff", "format", "--check", "."],
        [PY, "-m", "mypy", "core", "eval", "rules", "tasks.py"],
    ],
    "migrate": [[PY, "-m", "alembic", "upgrade", "head"]],
    "sandbox": [[PY, "-m", "core.sandbox.build"]],  # build .sandbox/ (Windows)
    # the page detonator's image (D1); needs Docker and the pinned Playwright base image
    "detonator": [["docker", "build", "-t", "lynceus-detonator:1.2.0", "infra/detonator"]],
    "serve": [
        [
            PY,
            "-m",
            "uvicorn",
            "core.api.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
            "--no-access-log",
            "--no-server-header",
        ]  # fmt: skip
    ],
    # extras beyond the five core tasks
    "fmt": [[PY, "-m", "ruff", "format", "."], [PY, "-m", "ruff", "check", "--fix", "."]],
    "secrets": [  # secret scan against .secrets.baseline; callers append the file names
        [
            PY,
            "-c",
            "import sys; from detect_secrets.pre_commit_hook import main; "
            "sys.exit(main(['--baseline', '.secrets.baseline', *sys.argv[1:]]))",
        ]
    ],
    # a fresh clone: everything from the hash-locked pylock.toml (H1 A5: the same bytes on every
    # machine), then the parser libraries (also checked against hashes)
    "deps": [
        [PY, "-m", "pip", "install", "--only-binary=:all:", "-r", "pylock.toml"],
        [
            PY,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "-r",
            "requirements-sandbox.txt",
        ],
    ],  # fmt: skip
    # after changing requirements*.txt: re-resolve and re-hash, then review the diff of pylock.toml
    "lock": [
        [
            PY,
            "-m",
            "pip",
            "lock",
            "-r",
            "requirements-dev.txt",
            "--only-binary=:all:",
            "-o",
            "pylock.toml",
        ],
    ],  # fmt: skip
    "hooks": [["git", "config", "core.hooksPath", ".githooks"]],  # once per clone
}
_SCAN_SKIP = (  # generated; third-party test vectors; file hashes that look like high-entropy keys
    "docs/schemas/",
    "docs/eval/",
    "tests/data/",
    "corpus/mail/manifest.jsonl",  # the .eml files themselves stay scanned
    "corpus/mail/pins.txt",
    "pylock.toml",  # sha256 of every locked wheel (H1 A5)
    "rules/learned/url_host.json",  # the sha256 of the shipped model weights (AI1 P1)
)


def run(task: str, extra: list[str]) -> int:
    cmds = list(TASKS[task])
    if (
        task == "test"
        and os.name == "nt"
        and not (ROOT / ".sandbox" / "runtime" / "python.exe").exists()
    ):
        cmds = [*TASKS["sandbox"], *cmds]  # the sandbox tests need the sandbox built once
    for i, cmd in enumerate(cmds):
        tail = extra if i == len(cmds) - 1 else []  # extra args go to the last command
        rc = subprocess.call(cmd + tail, cwd=ROOT)
        if rc:
            return rc
    return 0


def precommit() -> int:
    """Lint the tree, then secret-scan the staged files. Called by .githooks/pre-commit."""
    if rc := run("lint", []):
        return rc
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    files = [f for f in staged if not f.startswith(_SCAN_SKIP)]
    return run("secrets", files) if files else 0


def scan_all() -> int:
    """Secret-scan every tracked file, with the same skips as the hook (CI uses this)."""
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    files = [f for f in tracked if not f.startswith(_SCAN_SKIP)]
    rc = 0
    for i in range(0, len(files), 200):  # Windows caps a command line at 32,767 characters
        rc = rc or run("secrets", files[i : i + 200])
    return rc


def main(argv: list[str]) -> int:
    if argv[:1] == ["precommit"]:
        return precommit()
    if argv[:1] == ["scan-all"]:
        return scan_all()
    if not argv or argv[0] not in TASKS:
        print(f"usage: python tasks.py <{'|'.join(TASKS)}|precommit> [extra args]", file=sys.stderr)
        return 2
    return run(argv[0], argv[1:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
