<#
.SYNOPSIS  Runs before the MSI removes its files (uninstall and upgrade). Your data stays.
.DESCRIPTION
  Stops the agent that runs from this install, removes start-at-logon and the browser bridge, and
  deletes what Windows Installer does not know about: the sandbox folder (its permissions were
  changed at setup) and Python's compiled caches. The sandbox's per-user container profile is shared
  with any other MIRAGE install, so it is left alone (remove it with `python -m core.sandbox.build
  --remove` in a checkout). The data folder (%LOCALAPPDATA%\Mirage: quarantine, logs, token) and
  engine\.env are never removed.
.PARAMETER InstallDir   The folder the MSI installed to.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallDir)
$ErrorActionPreference = 'Continue'
$install = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$agentExe = Join-Path $install 'agent\Mirage.Agent.exe'
$home_ = if ($env:MIRAGE_AGENT_HOME) { $env:MIRAGE_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Mirage' }
New-Item -ItemType Directory -Force $home_ | Out-Null
$log = Join-Path $home_ 'setup.log'
function Say($text) { Add-Content -Path $log -Value "$(Get-Date -Format s) [cleanup] $text" }
function Test-IsUnder($path, $folder) {
    $p = [System.IO.Path]::GetFullPath($path).TrimEnd('\') + '\'
    $f = [System.IO.Path]::GetFullPath($folder).TrimEnd('\') + '\'
    $p.StartsWith($f, [System.StringComparison]::OrdinalIgnoreCase)
}

if (-not (Test-Path $agentExe)) { Say "$install has no agent\Mirage.Agent.exe: nothing done"; exit 0 }   # never touch a folder that is not ours
foreach ($p in @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-IsUnder $_.Path $install) })) {
    Say "stopping the agent ($($p.Id))"; & taskkill /PID $p.Id /T /F | Out-Null
}
Start-Sleep -Seconds 2
# --uninstall removes the registration by name, so only run it when the start-at-logon entry is THIS install's
$runValue = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).MirageAgent
if ($runValue -and (Test-IsUnder ($runValue.Trim('"')) $install)) {
    Say 'removing start-at-logon and the browser bridge'
    & $agentExe --uninstall
    Remove-Item -Path 'HKCU:\Software\Classes\AppUserModelId\Mirage.Agent' -Recurse -ErrorAction SilentlyContinue   # the toast sender name
} else {
    Say 'start-at-logon is not registered for this install: left alone'
}
$sandbox = Join-Path $install 'engine\.sandbox'
if (Test-Path $sandbox) { Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue; Say 'removed the sandbox folder' }
Get-ChildItem $install -Directory -Recurse -Force -Filter '__pycache__' -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
Say 'done'
exit 0
