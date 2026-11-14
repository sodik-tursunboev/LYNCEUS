"""H1 A5: every Python dependency installs from pylock.toml with a hash, at a version that meets the
human-readable lower bounds in requirements*.txt, and the parser libraries agree with their own
hash-pinned file. A requirement added without re-locking fails here."""

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).parents[2]
LOCK = tomllib.loads((ROOT / "pylock.toml").read_text(encoding="utf-8"))
LOCKED = {canonicalize_name(p["name"]): p for p in LOCK["packages"]}


def requirements(name: str) -> list[Requirement]:
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
    return [
        Requirement(s)
        for line in lines
        if (s := line.split("#")[0].strip()) and not s.startswith("-")
    ]


def test_every_locked_package_has_a_hashed_wheel_and_no_sdist() -> None:
    for name, p in LOCKED.items():
        assert p.get("wheels"), name
        assert "sdist" not in p, name  # source builds run code at install time
        for wheel in p["wheels"]:
            assert re.fullmatch(r"[0-9a-f]{64}", wheel["hashes"]["sha256"]), (name, wheel["name"])


def test_every_requirement_is_locked_at_a_version_it_allows() -> None:
    for req in requirements("requirements.txt") + requirements("requirements-dev.txt"):
        locked = LOCKED.get(canonicalize_name(req.name))
        assert locked, f"{req.name} is required but not in pylock.toml: run python tasks.py lock"
        assert req.specifier.contains(Version(locked["version"]), prereleases=True), req


def test_the_parser_libraries_agree_with_their_own_pins() -> None:
    text = (ROOT / "requirements-sandbox.txt").read_text(encoding="utf-8")
    for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", text, re.M):
        locked = LOCKED.get(canonicalize_name(name))
        assert locked is None or locked["version"] == version, (name, version, locked["version"])
