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
    "up": [["docker", "compose", "-f", COMPOSE, "up", "-d", "--wait"]],
    "test": [[PY, "-m", "pytest"]],
    "eval": [[PY, "-m", "eval"]],
    "lint": [
        [PY, "-m", "ruff", "check", "."],
        [PY, "-m", "ruff", "format", "--check", "."],
        [PY, "-m", "mypy", "core", "eval", "tasks.py"],
    ],
    "migrate": [[PY, "-m", "alembic", "upgrade", "head"]],
    # extras beyond the five core tasks
    "fmt": [[PY, "-m", "ruff", "check", "--fix", "."], [PY, "-m", "ruff", "format", "."]],
    "secrets": [  # secret scan against .secrets.baseline; callers append the file names
        [
            PY,
            "-c",
            "import sys; from detect_secrets.pre_commit_hook import main; "
            "sys.exit(main(['--baseline', '.secrets.baseline', *sys.argv[1:]]))",
        ]
    ],
    "hooks": [["git", "config", "core.hooksPath", ".githooks"]],  # once per clone
}
_SCAN_SKIP = ("docs/schemas/",)  # generated files: high-entropy ids, nothing to find


def run(task: str, extra: list[str]) -> int:
    cmds = TASKS[task]
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


def main(argv: list[str]) -> int:
    if argv[:1] == ["precommit"]:
        return precommit()
    if not argv or argv[0] not in TASKS:
        print(f"usage: python tasks.py <{'|'.join(TASKS)}|precommit> [extra args]", file=sys.stderr)
        return 2
    return run(argv[0], argv[1:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
