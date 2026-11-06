"""Stage the core for the MSI: a trimmed Python, only the libraries the core needs at run time, the
code, the console and the pre-built sandbox, laid out like the checkout so the core finds everything
relative to its own folder.

Run with the project's virtual environment: `.venv\\Scripts\\python.exe deploy\\msi\\stage_engine.py
<out-dir>`. It copies from what is already installed (no download) and refuses a stale sandbox.
"""

import hashlib
import shutil
import sys
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]
SKIP_STDLIB = {  # same list the sandbox build uses, plus what a server never imports
    "site-packages", "test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip",
    "__pycache__", "venv", "lib2to3",
}  # fmt: skip
CODE = ("core", "rules")
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


def runtime_closure() -> list[metadata.Distribution]:
    """The distributions named in requirements.txt and, recursively, what they need on this
    platform. Extras are followed (`psycopg[binary]`)."""
    names = [
        line.split("#")[0].strip()
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.split("#")[0].strip()
    ]
    todo = [Requirement(n) for n in names]
    seen: dict[str, metadata.Distribution] = {}
    wanted_extras: dict[str, set[str]] = {}
    while todo:
        req = todo.pop()
        key = canonicalize_name(req.name)
        extras = set(req.extras)
        if key in seen and extras <= wanted_extras[key]:
            continue
        dist = seen.get(key) or metadata.distribution(req.name)
        seen[key] = dist
        wanted_extras.setdefault(key, set()).update(extras)
        for line in dist.requires or []:
            sub = Requirement(line)
            if sub.marker is None:
                todo.append(sub)
                continue
            env = [{"extra": e} for e in sorted(wanted_extras[key])] or [{"extra": ""}]
            if any(sub.marker.evaluate(e) for e in env):
                todo.append(Requirement(str(sub).split(";")[0].strip()))
    return sorted(seen.values(), key=lambda d: d.metadata["Name"].lower())


def copy_distribution(dist: metadata.Distribution, site: Path) -> int:
    src_root = Path(str(dist.locate_file("")))
    count = 0
    for f in dist.files or []:
        parts = f.parts
        if parts[0] == ".." or "__pycache__" in parts or f.suffix == ".pyc":
            continue
        source = src_root / f
        if not source.is_file():
            continue
        target = site / f
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
    return count


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sandbox_is_current(sandbox: Path) -> None:
    guest = ROOT / "core" / "sandbox" / "guest"
    built = sandbox / "app"
    if not (sandbox / "runtime" / "python.exe").exists() or not built.is_dir():
        sys.exit("the sandbox is not built: run python tasks.py sandbox")
    for f in guest.rglob("*.py"):
        copy = built / f.relative_to(guest)
        if not copy.is_file() or sha(copy) != sha(f):
            sys.exit(f"the sandbox is stale ({f.name}): run python tasks.py sandbox")


def main(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    python = out / "python"
    base = Path(sys.base_prefix)
    python.mkdir(parents=True)
    for pattern in ("python.exe", "python3*.dll", "vcruntime*.dll"):
        for f in base.glob(pattern):
            shutil.copy2(f, python / f.name)
    shutil.copytree(base / "DLLs", python / "DLLs", ignore=IGNORE)
    shutil.copytree(
        base / "Lib", python / "Lib",
        ignore=lambda _d, names: [n for n in names if n in SKIP_STDLIB or n.endswith(".pyc")],
    )  # fmt: skip
    site = python / "Lib" / "site-packages"
    site.mkdir()
    total = 0
    for dist in runtime_closure():
        total += copy_distribution(dist, site)
        print(f"  {dist.metadata['Name']} {dist.version}")
    print(f"{total} library files")

    for name in CODE:
        shutil.copytree(ROOT / name, out / name, ignore=IGNORE)
    shutil.copytree(ROOT / "console" / "dist", out / "console" / "dist")
    shutil.copy2(ROOT / "alembic.ini", out / "alembic.ini")
    sandbox = ROOT / ".sandbox"
    check_sandbox_is_current(sandbox)
    shutil.copytree(sandbox, out / ".sandbox", ignore=IGNORE)  # no .env is ever copied


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]).resolve())
