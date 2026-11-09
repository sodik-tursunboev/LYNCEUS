"""Rules about what is INSIDE a file or an archive entry: its code, hidden layers, macros, shortcut
commands and executables, and exact matches against known-bad hash lists.

The sandbox reads the content and reports counts of fixed indicator names (never the code). Rules
here look for combinations rather than single words: a script that downloads and also runs something
is a dropper, a script that only mentions a download is an administrator's helper. Summaries use
numbers and fixed words; never code, file names or addresses.
"""

from collections.abc import Callable

from core.email.models import ArchiveScan, ContentScan, Indicator
from rules.email import (
    CREDENTIAL_DUMP,
    DDE,
    EMBEDDED_PAYLOAD,
    GUI_INPUT,
    HIDDEN_WINDOW,
    IMPAIR_DEFENSES,
    INGRESS_TOOL,
    INJECTION,
    MALICIOUS_FILE,
    MASQUERADE_FILE_TYPE,
    NATIVE_API,  # noqa: E402  (kept apart: one more name for the macro rules)
    OBFUSCATION,
    OFFICE_STARTUP,
    PACKING,
    PROXY_EXECUTION,
    RUN_KEY,
    SANDBOX_EVASION,
    SCRIPTING,
    TEMPLATE_INJECTION,
    VBA_STOMPING,
    Ctx,
    rule,
)
from rules.email.attachments import DOCUMENT_LOOKING, file_ext

PROGRAMS = frozenset({"vbscript", "jscript", "powershell", "batch", "hta", "wsf", "lnk"})
Test = Callable[[ContentScan], bool]


def _scans(ctx: Ctx) -> list[tuple[str, ContentScan, str]]:
    """Every content scan reachable: whole files, and the entries of archives."""
    out: list[tuple[str, ContentScan, str]] = []
    for f in ctx.files:
        if isinstance(f.scan, ContentScan):
            out.append((f.part, f.scan, "file"))
        elif isinstance(f.scan, ArchiveScan):
            out += [(f.part, m.content, "entry") for m in f.scan.members if m.content]
    return out


def _count(ctx: Ctx, test: Test) -> tuple[int, ContentScan | None]:
    hits = [s for _, s, _ in _scans(ctx) if test(s)]
    return len(hits), (hits[0] if hits else None)


def _has(s: ContentScan, *names: Indicator) -> bool:
    return any(s.indicators.get(n, 0) for n in names)


def _where(ctx: Ctx, test: Test) -> str:
    kinds = {w for _, s, w in _scans(ctx) if test(s)}
    return "inside an archive" if kinds == {"entry"} else "in a file"


def _said(n: int, text: str) -> str | None:
    return text.format(n=n) if n else None


# ---- exact identification ----------------------------------------------------------------------
@rule("intel.hash_known_bad", "known_bad", MALICIOUS_FILE)
def hash_known_bad(ctx: Ctx) -> str | None:
    if not ctx.known_bad:
        return None
    sources = sorted({h.source for h in ctx.known_bad})
    kinds = sorted({h.where for h in ctx.known_bad})
    return (
        f"{len(ctx.known_bad)} {' and '.join(kinds)} whose hash is on the known-bad list "
        f"{', '.join(sources[:3])}"
    )


@rule("content.eicar", "known_bad", MALICIOUS_FILE)
def eicar(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: s.eicar)
    return _said(n, "{n} copy of the EICAR antivirus test file (harmless by design)")


# ---- scripts and what they do ------------------------------------------------------------------
@rule("content.script_downloader", "code_behavior", INGRESS_TOOL)
def script_downloader(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return _has(s, "download") and _has(
            s, "exec_shell", "execute_dynamic", "persistence", "lolbin_proxy", "encoded_command"
        )

    n, _ = _count(ctx, test)
    return _said(
        n,
        "{n} script(s) " + _where(ctx, test) + " that fetch something from the Internet and run it",
    )


@rule("content.script_encoded", "obfuscation", SCRIPTING)
def script_encoded(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return _has(s, "encoded_command") or (
            _has(s, "base64_decode") and _has(s, "execute_dynamic")
        )

    n, _ = _count(ctx, test)
    return _said(n, "{n} script(s) " + _where(ctx, test) + " that decode hidden text and run it")


@rule("content.script_hidden_layers", "obfuscation", OBFUSCATION)
def script_hidden_layers(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return s.family in PROGRAMS | {"html", "ole"} and (
            s.layers > 0 or _has(s, "string_obfuscation", "high_entropy_blob")
        )

    n, first = _count(ctx, test)
    if not n or first is None:
        return None
    return (
        f"{n} {first.family} item(s) {_where(ctx, test)} hide code behind "
        f"{max(first.layers, 1)} layer(s) of encoding or string tricks"
    )


@rule("content.script_evasive_launch", "evasion", HIDDEN_WINDOW)
def script_evasive_launch(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return _has(s, "hidden_window", "bypass_policy") and _has(s, "exec_shell", "download")

    n, _ = _count(ctx, test)
    return _said(
        n, "{n} script(s) that start programs with a hidden window or with safety settings bypassed"
    )


@rule("content.script_persistence", "persistence", RUN_KEY)
def script_persistence(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return _has(s, "persistence") and _has(
            s, "download", "exec_shell", "execute_dynamic", "encoded_command"
        )

    n, _ = _count(ctx, test)
    return _said(n, "{n} script(s) that make themselves run again at start-up or on a schedule")


@rule("content.script_lolbin", "evasion", PROXY_EXECUTION)
def script_lolbin(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "lolbin_proxy"))
    return _said(
        n, "{n} script(s) that run code through trusted Windows programs (mshta, regsvr32)"
    )


@rule("content.defense_evasion", "evasion", IMPAIR_DEFENSES)
def defense_evasion(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "defense_evasion"))
    return _said(
        n, "{n} item(s) that try to switch off or blind the antivirus (AMSI, Defender, logs)"
    )


@rule("content.process_injection", "code_behavior", INJECTION)
def process_injection(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "process_injection") and s.family != "pe")
    return _said(n, "{n} item(s) with code that writes into other running programs")


@rule("content.credential_access", "code_behavior", CREDENTIAL_DUMP)
def credential_access(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "credential_access"))
    return _said(n, "{n} item(s) that go after stored Windows credentials")


@rule("content.credential_prompt", "deception", GUI_INPUT)
def credential_prompt(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "credential_prompt") and s.family in PROGRAMS)
    return _said(n, "{n} script(s) that pop up a password prompt")


@rule("content.anti_analysis", "evasion", SANDBOX_EVASION)
def anti_analysis(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "anti_analysis") and s.family in PROGRAMS)
    return _said(
        n, "{n} script(s) that look for virtual machines or debuggers, or delay themselves"
    )


@rule("content.embedded_executable", "code_behavior", EMBEDDED_PAYLOAD)
def embedded_executable(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return s.family != "pe" and bool(s.embedded.get("exe", 0) or s.embedded.get("elf", 0))

    n, _ = _count(ctx, test)
    return _said(n, "{n} item(s) with a Windows or Linux program hidden inside")


@rule("content.disguised_program", "deception", MASQUERADE_FILE_TYPE)
def disguised_program(ctx: Ctx) -> str | None:
    """A script or shortcut whose name says it is a document or a picture."""
    names = {p.path: file_ext(p.filename) for p in ctx.scan.parts}
    n = 0
    for f in ctx.files:
        if isinstance(f.scan, ContentScan) and f.scan.family in PROGRAMS:
            n += names.get(f.part, "") in DOCUMENT_LOOKING
        elif isinstance(f.scan, ArchiveScan):
            n += sum(
                1
                for m in f.scan.members
                if m.content and m.content.family in PROGRAMS and m.ext in DOCUMENT_LOOKING
            )
    return _said(n, "{n} script(s) or shortcut(s) named like a document or picture")


# ---- Office files and RTF ----------------------------------------------------------------------
def _macro(s: ContentScan) -> bool:
    return s.family in ("ole", "xlm") and _has(s, "macro_code")


def _archives(ctx: Ctx, test: Callable[[ArchiveScan], bool]) -> int:
    return sum(isinstance(f.scan, ArchiveScan) and test(f.scan) for f in ctx.files)


@rule("content.office_macro", "attachment", OFFICE_STARTUP)
def office_macro(ctx: Ctx) -> str | None:
    n = _count(ctx, _macro)[0] + _archives(ctx, lambda a: a.vba_project)
    return _said(n, "{n} Office file(s) that carry a macro project, whatever their name says")


@rule("content.office_macro_autoexec", "code_behavior", MALICIOUS_FILE)
def office_macro_autoexec(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return (
            _macro(s)
            and _has(s, "autoexec")
            and _has(
                s,
                "exec_shell",
                "download",
                "execute_dynamic",
                "process_injection",
                "lolbin_proxy",
                "encoded_command",
            )  # fmt: skip
        )

    n, _ = _count(ctx, test)
    return _said(n, "{n} Office file(s) with a macro that runs on opening and starts programs")


# ---- macros no list knows: what reading their code gives away (ADR-023) -------------------------
_RUNS: tuple[Indicator, ...] = (
    "exec_shell", "download", "execute_dynamic", "process_injection", "lolbin_proxy",
)  # fmt: skip


@rule("content.macro_hidden_behavior", "obfuscation", OBFUSCATION)
def macro_hidden_behavior(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _macro(s) and _has(s, "macro_hidden_behavior"))
    return _said(
        n,
        "{n} macro(s) whose own decoder builds a command that cannot be seen in their text "
        "(it only appears when their string-building code is followed)",
    )


@rule("content.macro_autoexec_reaches_sink", "code_behavior", MALICIOUS_FILE)
def macro_autoexec_reaches_sink(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _macro(s) and _has(s, "macro_autoexec_reaches_sink"))
    return _said(
        n,
        "{n} macro(s) that start by themselves and, through the code they call, run programs, "
        "download something or inject code",
    )


@rule("content.macro_api_import", "api_abuse", NATIVE_API)
def macro_api_import(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _macro(s) and _has(s, "win32_api_import", "process_injection"))
    return _said(
        n, "{n} macro(s) that import Windows functions for loading code or running programs"
    )


@rule("content.macro_dynamic_dispatch", "evasion", OBFUSCATION)
def macro_dynamic_dispatch(ctx: Ctx) -> str | None:
    n, _ = _count(
        ctx, lambda s: _macro(s) and _has(s, "macro_dynamic_dispatch") and _has(s, "autoexec")
    )
    return _said(
        n, "{n} self-starting macro(s) that call things whose names they work out while running"
    )


@rule("content.macro_hidden_data_source", "evasion", OBFUSCATION)
def macro_hidden_data_source(ctx: Ctx) -> str | None:
    def test(s: ContentScan) -> bool:
        return (
            _macro(s)
            and _has(s, "macro_hidden_data_source")
            and (
                _has(s, *_RUNS) or _has(s, "macro_dynamic_dispatch", "macro_autoexec_reaches_sink")
            )
        )

    n, _ = _count(ctx, test)
    return _said(
        n,
        "{n} macro(s) that read data from document properties, form fields or hidden parts "
        "and run things",
    )


@rule("content.macro_file_drop", "persistence", INGRESS_TOOL)
def macro_file_drop(ctx: Ctx) -> str | None:
    n, _ = _count(
        ctx,
        lambda s: (
            _macro(s)
            and _has(s, "macro_file_drop")
            and _has(s, *_RUNS, "macro_autoexec_reaches_sink")
        ),
    )
    return _said(
        n, "{n} macro(s) that write a file into a temporary or start-up folder and run things"
    )


@rule("content.macro_obfuscated", "obfuscation", OBFUSCATION)
def macro_obfuscated(ctx: Ctx) -> str | None:
    n, _ = _count(
        ctx, lambda s: _macro(s) and _has(s, "macro_obfuscated_code") and _has(s, "autoexec")
    )
    return _said(n, "{n} self-starting macro(s) whose code looks scrambled on purpose")


@rule("content.vba_stomped", "evasion", VBA_STOMPING)
def vba_stomped(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "vba_stomped"))
    return _said(n, "{n} macro(s) whose compiled code says something the readable source does not")


@rule("content.vba_pcode_only", "evasion", VBA_STOMPING)
def vba_pcode_only(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "vba_pcode_only"))
    return _said(n, "{n} macro(s) that carry compiled code and no readable source")


@rule("content.xlm_macro", "active_content", OFFICE_STARTUP)
def xlm_macro(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "xlm_macro"))
    return _said(
        n, "{n} workbook(s) with an Excel 4.0 macro sheet (formulas that can run programs)"
    )


@rule("content.xlm_hidden", "evasion", OBFUSCATION)
def xlm_hidden(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "xlm_hidden"))
    return _said(n, "{n} workbook(s) that hide their Excel 4.0 macro sheet")


@rule("content.office_remote_template", "code_behavior", TEMPLATE_INJECTION)
def office_remote_template(ctx: Ctx) -> str | None:
    n = (
        _archives(ctx, lambda a: a.remote_template)
        + _count(ctx, lambda s: _has(s, "remote_template"))[0]
    )
    return _said(n, "{n} document(s) that load a template or object from the Internet when opened")


@rule("content.office_dde", "code_behavior", DDE)
def office_dde(ctx: Ctx) -> str | None:
    n = _archives(ctx, lambda a: a.dde)
    return _said(n, "{n} document(s) with a DDE field (it can run a command when opened)")


@rule("content.equation_editor", "code_behavior", MALICIOUS_FILE)
def equation_editor(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "equation_editor"))
    return _said(n, "{n} document(s) with an Equation Editor object (a classic exploit carrier)")


@rule("content.ole_object", "attachment", MALICIOUS_FILE)
def ole_object(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "ole_object"))
    return _said(n, "{n} document(s) with an embedded or linked object")


# ---- shortcuts and programs --------------------------------------------------------------------
@rule("content.lnk_runs_interpreter", "code_behavior", MALICIOUS_FILE)
def lnk_runs_interpreter(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "lnk_interpreter"))
    return _said(n, "{n} shortcut(s) whose real job is to run a command interpreter with arguments")


@rule("content.lnk_disguised", "deception", MASQUERADE_FILE_TYPE)
def lnk_disguised(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "lnk_icon_lure", "lnk_hidden_args"))
    return _said(n, "{n} shortcut(s) with a document icon or arguments padded to hide them")


@rule("content.pe_packed", "obfuscation", PACKING)
def pe_packed(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "pe_packed", "pe_rwx", "pe_overlay"))
    return _said(n, "{n} program(s) that look packed or carry a large hidden tail")


@rule("content.pe_injection_or_downloader", "code_behavior", INJECTION)
def pe_injection_or_downloader(ctx: Ctx) -> str | None:
    n, _ = _count(ctx, lambda s: _has(s, "pe_injection_apis", "pe_downloader_apis"))
    return _said(n, "{n} program(s) importing functions typical of injecting code or downloading")
