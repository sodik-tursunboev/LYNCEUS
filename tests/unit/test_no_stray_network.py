"""SECURITY NOTE in M1.md and ADR-015: network code lives in two files only.

safe_fetch (the redirect resolver) is off and unwired; core/intel/http.py is the one place
threat-intelligence providers open connections, and only for providers the operator enabled."""

import ast
from pathlib import Path

from core.api.app import AnalyzeRequest

ROOT = Path(__file__).parents[2]
NETWORK_MODULES = {"socket", "ssl", "httpx", "httpcore", "requests", "aiohttp", "urllib3"}
NETWORK_SUBMODULES = {"urllib.request", "http.client", "ftplib", "smtplib"}
ALLOWED = {ROOT / "core" / "urls" / "safe_fetch.py", ROOT / "core" / "intel" / "http.py"}


def imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_only_the_two_network_modules_open_connections() -> None:
    for package in ("core", "rules", "eval"):
        for path in (ROOT / package).rglob("*.py"):
            if path in ALLOWED:
                continue
            found = imports(path)
            bad = {n for n in found if n.split(".")[0] in NETWORK_MODULES} | (
                found & NETWORK_SUBMODULES
            )
            assert not bad, f"{path}: {bad}"


def test_nothing_calls_safe_fetch_yet() -> None:
    """Unwired on purpose (decision D3). Wiring it in needs ADR-011 signed off."""
    for package in ("core", "rules", "eval"):
        for path in (ROOT / package).rglob("*.py"):
            assert "core.urls.safe_fetch" not in imports(path), path


def test_the_api_has_no_fetch_option() -> None:
    assert set(AnalyzeRequest.model_fields) == {"url"}


def test_only_intelligence_code_uses_the_intelligence_http_module() -> None:
    """Whatever calls out does so through the bounded, redirect-free client and nowhere else."""
    users = {
        path.relative_to(ROOT).as_posix()
        for package in ("core", "rules", "eval")
        for path in (ROOT / package).rglob("*.py")
        if "core.intel.http" in imports(path)
    }
    assert all(u.startswith("core/intel/") for u in users), users


def test_the_analysis_engines_do_not_import_intelligence() -> None:
    """The URL and message engines stay offline: intelligence is added around them, never inside."""
    for engine in ("core/detection/engine.py", "core/email/engine.py"):
        assert not any(n.startswith("core.intel") for n in imports(ROOT / engine)), engine
