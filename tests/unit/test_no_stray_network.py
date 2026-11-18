"""SECURITY NOTE in M1.md, ADR-015 and ADR-017: network code lives in a few named files only.

safe_fetch (the redirect resolver) is off and unwired; core/intel/http.py is the one place
threat-intelligence providers open connections, and only for providers the operator enabled;
core/mailbox/gmail.py, oauth.py, graph.py and ms_oauth.py are the only places the live mailbox
talks to Google or Microsoft (fixed hosts, GET-only to the mail APIs), and only when the operator
connected an account (M5, M5b); core/mailbox/write.py is the one place a mailbox is changed (M6b),
behind its own narrow request guard that the tests try with every forbidden request;
eval/perf.py is a measurement tool that talks only to a local server it starts itself (M7);
core/llm/ollama.py reaches a local model through core/intel/http.py and only on a loopback address
(ADR-023); eval/detonate.py downloads the two public phishing lists for the D1 measurement and
nothing else (the pages themselves are opened only inside the detonator container, ADR-025)."""

import ast
from pathlib import Path

from core.api.app import AnalyzeRequest

ROOT = Path(__file__).parents[2]
NETWORK_MODULES = {"socket", "ssl", "httpx", "httpcore", "requests", "aiohttp", "urllib3"}
NETWORK_SUBMODULES = {"urllib.request", "http.client", "ftplib", "smtplib"}
ALLOWED = {
    ROOT / "core" / "urls" / "safe_fetch.py",
    ROOT / "core" / "intel" / "http.py",
    ROOT / "core" / "mailbox" / "gmail.py",
    ROOT / "core" / "mailbox" / "oauth.py",
    ROOT / "core" / "mailbox" / "graph.py",  # Microsoft Graph, GET only (M5b)
    ROOT / "core" / "mailbox" / "ms_oauth.py",
    ROOT / "core" / "mailbox" / "write.py",  # the narrow write guard and the two movers (M6b)
    ROOT / "eval" / "perf.py",  # loopback only: checked by the test below
    ROOT / "eval" / "detonate.py",  # the two phishing lists only: checked by the test below
    ROOT / "eval" / "deeplinks.py",  # the Internet Archive's public index only: checked below (DA2)
}


def imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_only_the_named_network_modules_open_connections() -> None:
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
    """Whatever calls out does so through the bounded, redirect-free client and nowhere else. The
    one user outside core/intel is the local-model client (ADR-023), which can only be built for a
    loopback address: tests/unit/test_llm_advisor.py tries every other kind of address."""
    users = {
        path.relative_to(ROOT).as_posix()
        for package in ("core", "rules", "eval")
        for path in (ROOT / package).rglob("*.py")
        if "core.intel.http" in imports(path)
    }
    assert all(u.startswith("core/intel/") or u == "core/llm/ollama.py" for u in users), users


def test_the_analysis_engines_do_not_import_the_local_model() -> None:
    """The engines decide by rules. A model is used only AROUND them: the macro advice (ADR-023) and
    the checked brain (AI1, ADR-027), wired in by the API and, for the brain, the mailbox wiring;
    never inside an engine, the poller's sync code or a rule."""
    for path in [*(ROOT / "rules").rglob("*.py"), *(ROOT / "core").rglob("*.py")]:
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(("core/llm/", "core/brain/")) or rel == "core/api/app.py":
            continue
        names = imports(path)
        assert not any(n.startswith("core.llm") for n in names), rel
        if rel != "core/mailbox/wiring.py":  # the one place the poller's analysis gets the brain
            assert not any(n.startswith("core.brain") for n in names), rel


def test_the_analysis_engines_do_not_import_intelligence() -> None:
    """The URL and message engines stay offline: intelligence is added around them, never inside."""
    for engine in ("core/detection/engine.py", "core/email/engine.py"):
        assert not any(n.startswith("core.intel") for n in imports(ROOT / engine)), engine


def test_the_mailbox_reaches_the_network_only_through_its_two_guarded_modules() -> None:
    """Sync, service and storage code never open connections: they use the guarded client."""
    mailbox = ROOT / "core" / "mailbox"
    for path in mailbox.glob("*.py"):
        if path.name in ("gmail.py", "oauth.py", "graph.py", "ms_oauth.py", "write.py"):
            continue
        bad = {n for n in imports(path) if n.split(".")[0] in NETWORK_MODULES} - set()
        assert not bad, f"{path}: {bad}"
    users = {
        path.relative_to(ROOT).as_posix()
        for package in ("core", "rules", "eval")
        for path in (ROOT / package).rglob("*.py")
        if imports(path) & {"core.mailbox.gmail", "core.mailbox.oauth", "core.mailbox.graph"}
    }
    assert all(u.startswith("core/mailbox/") for u in users), users


def test_the_analysis_engines_do_not_import_the_mailbox() -> None:
    for engine in ("core/detection/engine.py", "core/email/engine.py", "core/files/engine.py"):
        assert not any(n.startswith("core.mailbox") for n in imports(ROOT / engine)), engine


def test_the_measurement_tool_only_ever_connects_to_this_machine() -> None:
    """Every address passed to urlopen/Request in eval/perf.py starts with http://127.0.0.1:
    (the sample URLs it analyses are data, never connected to)."""
    tree = ast.parse((ROOT / "eval" / "perf.py").read_text(encoding="utf-8"))
    targets = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") in ("urlopen", "Request"):
            first = node.args[0] if node.args else None
            if isinstance(first, ast.JoinedStr):
                head = first.values[0]
                targets.append(head.value if isinstance(head, ast.Constant) else "?")
            elif isinstance(first, ast.Constant):
                targets.append(str(first.value))
    assert len(targets) >= 2, targets
    assert all(str(x).startswith("http://127.0.0.1:") for x in targets), targets


def test_the_deep_link_builder_only_asks_the_archives_public_index() -> None:
    """eval/deeplinks.py (DA2) may use httpx in fetch() and build() only, and only for one fixed
    endpoint: the Internet Archive's public CDX index, asked about public Tranco domain names. It
    reads nothing of the owner's."""
    from urllib.parse import urlsplit

    from eval.deeplinks import CDX

    assert urlsplit(CDX).hostname == "web.archive.org" and urlsplit(CDX).scheme == "https"
    tree = ast.parse((ROOT / "eval" / "deeplinks.py").read_text(encoding="utf-8"))
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        uses = any(isinstance(x, ast.Name) and x.id == "httpx" for x in ast.walk(fn))
        assert not uses or fn.name in ("fetch", "build"), fn.name
    text = (ROOT / "eval" / "deeplinks.py").read_text(encoding="utf-8")
    assert "edge_history" not in text  # no browsing history anywhere in this tool


def test_the_detonation_measurement_only_downloads_the_two_phishing_lists() -> None:
    """eval/detonate.py may use httpx in refresh() only, and only for its fixed SOURCES (OpenPhish
    and PhishTank, as in E1). Pages are never fetched here: they are opened in the container."""
    from urllib.parse import urlsplit

    from eval.detonate import SOURCES

    hosts = {urlsplit(u).hostname for u in SOURCES.values()}
    assert hosts == {"raw.githubusercontent.com", "data.phishtank.com"}, hosts
    tree = ast.parse((ROOT / "eval" / "detonate.py").read_text(encoding="utf-8"))
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        uses = any(isinstance(x, ast.Name) and x.id == "httpx" for x in ast.walk(fn))
        assert not uses or fn.name == "refresh", fn.name
