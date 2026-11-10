"""The deploy scripts' safety helpers (independent review R1): who can change the folder the core
runs from, that an uninstall only ever deletes what is certainly Lynceus's, and that quarantined
files are not deleted by accident. Everything runs against folders made under pytest's temp
directory, never the real install or data folder, and with -NoRegister so the registry is not
touched."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

DEPLOY = Path(__file__).parents[2] / "deploy"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell scripts")


def ps(script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    import os

    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=120, env={**os.environ, **(env or {})},
    )  # fmt: skip


def helpers(body: str) -> str:
    return f". '{DEPLOY / 'Acl.ps1'}'; {body}"


def test_a_folder_others_can_change_is_reported_and_can_be_restricted(tmp_path: Path) -> None:
    folder = tmp_path / "checkout"
    folder.mkdir()
    (folder / "app.py").write_text("print(1)", encoding="utf-8")
    listing = f"(Get-ChangeableByOthers '{folder}') -join ','"
    quiet = ps(helpers(listing))
    assert quiet.returncode == 0 and quiet.stdout.strip() == ""  # a profile temp folder: only you

    # what a folder directly under C:\ looks like by default: every signed-in account may change it
    grant = subprocess.run(
        ["icacls", str(folder), "/grant", "*S-1-5-11:(OI)(CI)M"], capture_output=True, text=True
    )
    assert grant.returncode == 0, grant.stdout
    loud = ps(helpers(f"(Get-ChangeableByOthers '{folder}') -join ','"))
    assert "Authenticated Users" in loud.stdout

    fixed = ps(helpers(f"Protect-Folder '{folder}'; (Get-ChangeableByOthers '{folder}') -join ','"))
    assert fixed.returncode == 0 and fixed.stdout.strip() == "", fixed.stderr
    acl = subprocess.run(["icacls", str(folder)], capture_output=True, text=True).stdout
    assert "Authenticated Users" not in acl and "BUILTIN\\Users" not in acl
    (folder / "after.txt").write_text("you can still work here", encoding="utf-8")  # not locked out
    assert (folder / "app.py").read_text(encoding="utf-8") == "print(1)"


def test_permissions_inherited_from_the_parent_are_removed_too_as_on_a_folder_under_c() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as parent_name:
        parent = Path(parent_name)
        # the parent grants every signed-in account Modify, inheritable: what C:\ does by default
        grant = subprocess.run(
            ["icacls", str(parent), "/grant", "*S-1-5-11:(OI)(CI)M"], capture_output=True, text=True
        )
        assert grant.returncode == 0, grant.stdout
        folder = parent / "checkout"
        folder.mkdir()
        listing = f"(Get-ChangeableByOthers '{folder}') -join ','"
        assert "Authenticated Users" in ps(helpers(listing)).stdout  # it arrives by inheritance
        fixed = ps(helpers(f"Protect-Folder '{folder}'; {listing}"))
        assert fixed.returncode == 0 and fixed.stdout.strip() == "", fixed.stderr
        (folder / "after.txt").write_text("still yours", encoding="utf-8")


def test_under_needs_a_separator_so_a_sibling_name_is_not_inside() -> None:
    out = ps(
        helpers(
            "(Test-IsUnder 'C:\\a\\bc' 'C:\\a\\b'), (Test-IsUnder 'C:\\a\\b\\c' 'C:\\a\\b'), "
            "(Test-IsUnder 'C:\\a\\b' 'C:\\a\\b'), "
            "(Test-IsUnder 'C:\\A\\B\\c' 'c:\\a\\b') -join ','"
        )
    )
    assert out.stdout.strip() == "False,True,True,True"


def quarantine_record(root: Path, name: str, state: str | None, raw: str | None = None) -> None:
    folder = root / "quarantine" / name
    folder.mkdir(parents=True)
    (folder / "record.json").write_text(raw if raw is not None else json.dumps({"state": state}))


def test_quarantined_files_that_were_not_restored_are_counted_and_an_unreadable_record_counts_too(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    quarantine_record(data, "a", "quarantined")
    quarantine_record(data, "b", "restored")
    quarantine_record(data, "c", "moving")
    quarantine_record(data, "d", None, raw="{ not json")  # never guess: unreadable is unrestored
    out = ps(helpers(f"Get-UnrestoredCount '{data}'"))
    assert out.stdout.strip() == "3"
    assert ps(helpers(f"Get-UnrestoredCount '{tmp_path / 'nothing'}'")).stdout.strip() == "0"


def uninstall(install: Path, data: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    return ps(
        f"& '{DEPLOY / 'uninstall.ps1'}' -InstallDir '{install}' -NoRegister {' '.join(flags)}",
        env={"LYNCEUS_AGENT_HOME": str(data)},
    )


def test_uninstall_refuses_a_folder_that_is_not_a_lynceus_install(tmp_path: Path) -> None:
    other = tmp_path / "my-projects"
    other.mkdir()
    (other / "important.txt").write_text("not yours to delete", encoding="utf-8")
    result = uninstall(other, tmp_path / "data")
    assert result.returncode != 0 and "does not look like a Lynceus install" in result.stderr
    assert (other / "important.txt").read_text(encoding="utf-8") == "not yours to delete"

    real = tmp_path / "install"
    (real / "agent").mkdir(parents=True)
    (real / "agent" / "Lynceus.Agent.exe").write_bytes(b"MZ")
    assert uninstall(real, tmp_path / "data").returncode == 0
    assert not real.exists()  # a real install is removed


def test_remove_data_keeps_quarantined_files_unless_forced_and_never_deletes_a_foreign_folder(
    tmp_path: Path,
) -> None:
    install = tmp_path / "install"
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent.json").write_text("{}", encoding="utf-8")
    quarantine_record(data, "x", "quarantined")
    (data / "quarantine" / "x" / "payload.quar").write_bytes(b"the only copy")

    refused = uninstall(install, data, "-RemoveData")
    assert refused.returncode != 0 and "have not been restored" in refused.stderr
    assert (data / "quarantine" / "x" / "payload.quar").read_bytes() == b"the only copy"

    forced = uninstall(install, data, "-RemoveData", "-Force")
    assert forced.returncode == 0 and not data.exists()

    foreign = tmp_path / "documents"
    foreign.mkdir()
    (foreign / "thesis.docx").write_bytes(b"years of work")
    result = uninstall(install, foreign, "-RemoveData", "-Force")
    assert result.returncode != 0 and "does not look like a Lynceus data folder" in result.stderr
    assert (foreign / "thesis.docx").read_bytes() == b"years of work"


# ---- registration is checked through Windows' own view (ADR-024) --------------------------------
def registry(body: str) -> str:
    return f". '{DEPLOY / 'RegistryView.ps1'}'; {body}"


def test_the_registry_probe_answers_and_leaves_nothing_behind() -> None:
    script = (
        "$r = Test-RegistryReachesWindows; "
        "$left = @(Get-ChildItem HKCU:\\Software | "
        "Where-Object { $_.PSChildName -like 'Lynceus.RegistryProbe*' }).Count; "
        "if ($null -eq $r) { 'unknown' } else { [string]$r }; $left"
    )
    done = ps(registry(script))
    answer, left = done.stdout.split()
    assert done.returncode == 0 and answer in ("True", "False", "unknown") and left == "0", (
        done.stderr
    )


def test_what_windows_has_registered_is_read_as_nine_plain_facts() -> None:
    done = ps(registry("Get-LynceusRegistration | ConvertTo-Json -Compress"))
    facts = json.loads(done.stdout)
    assert set(facts) == {
        "RunLynceus", "RunTarget", "RunOldName", "EdgeBridge", "ChromeBridge", "EdgeOldName",
        "ChromeOldName", "Sandbox", "SandboxOld",
    }  # fmt: skip
    assert all(isinstance(v, bool) for k, v in facts.items() if k != "RunTarget")


def test_go_live_check_only_changes_nothing_and_says_how_it_stands() -> None:
    def state() -> str:
        return ps(registry("Get-LynceusRegistration | ConvertTo-Json -Compress")).stdout

    before = state()
    done = ps(f"& '{DEPLOY / 'go-live.ps1'}' -CheckOnly")
    assert done.returncode in (0, 1) and "GO-LIVE" in done.stdout, done.stderr
    assert "starts at logon" in done.stdout and state() == before


def test_the_installer_and_go_live_refuse_a_private_registry_before_changing_anything() -> None:
    """Both scripts ask first whether what they register would reach Windows (the text is checked,
    since whether THIS shell has a private registry depends on where the tests are run from)."""
    for name in ("install.ps1", "go-live.ps1"):
        text = (DEPLOY / name).read_text(encoding="utf-8")
        guard = text.index("Test-RegistryReachesWindows")
        for later in ("taskkill", "--install", "Start-Process", "Copy-Item"):
            assert later not in text[:guard], (name, later)
