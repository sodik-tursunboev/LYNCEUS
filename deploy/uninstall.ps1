<#
.SYNOPSIS  Remove what install.ps1 added. Your data (quarantine, logs, spool) stays unless you ask.
.PARAMETER InstallDir   The folder install.ps1 used. Default: %LOCALAPPDATA%\Programs\Mirage
.PARAMETER NoRegister   Do not touch the registry.
.PARAMETER RemoveData   Also delete the data folder, INCLUDING THE QUARANTINE FOLDER: files in it are gone for good.
                        Refused while files are still quarantined (restore them in the console first) unless -Force is also given.
.PARAMETER Force        With -RemoveData: delete even if quarantined files have not been restored.
.PARAMETER RemoveSandbox Also remove the parser sandbox (the AppContainer profile and this checkout's .sandbox folder).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Mirage'),
    [switch]$NoRegister,
    [switch]$RemoveData,
    [switch]$Force,
    [switch]$RemoveSandbox
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Acl.ps1')
function Say($text) { Write-Host "[uninstall] $text" }
$installFull = [System.IO.Path]::GetFullPath($InstallDir)
$agentExe = Join-Path $installFull 'agent\Mirage.Agent.exe'
foreach ($p in @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-IsUnder $_.Path $installFull) })) {
    Say "stopping the agent ($($p.Id))"; & taskkill /PID $p.Id /T /F | Out-Null
}
Start-Sleep -Seconds 2
if ((-not $NoRegister) -and (Test-Path $agentExe)) { Say 'removing start-at-logon and the browser bridge'; & $agentExe --uninstall }
if (Test-Path $installFull) {
    # only ever delete what is certainly a MIRAGE install: a wrong -InstallDir must not wipe another folder
    if (-not (Test-MirageInstall $installFull)) { throw "$installFull does not look like a MIRAGE install (no agent\Mirage.Agent.exe): nothing was deleted" }
    Remove-Item $installFull -Recurse -Force; Say "removed $installFull"
}
if (-not $NoRegister) { Remove-Item -Path 'HKCU:\Software\Classes\AppUserModelId\Mirage.Agent' -Recurse -ErrorAction SilentlyContinue }   # the toast sender name
$home_ = if ($env:MIRAGE_AGENT_HOME) { $env:MIRAGE_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Mirage' }
if ($RemoveData) {
    if (Test-Path $home_) {
        if (-not (Test-MirageData $home_)) { throw "$home_ does not look like a MIRAGE data folder: nothing was deleted" }
        $left = Get-UnrestoredCount $home_
        if ($left -and -not $Force) {
            throw "$left quarantined file(s) have not been restored, and the quarantine folder holds their only copy. Restore what you want from the console first, or run again with -Force to delete them for good. Nothing was deleted."
        }
        Remove-Item $home_ -Recurse -Force; Say "removed the data folder $home_ (quarantined files included)"
    }
} else {
    Say "kept your data in $home_ (logs, spool, token, quarantine). Delete it yourself, or run again with -RemoveData."
}
if ($RemoveSandbox) {
    $repo = Split-Path -Parent $PSScriptRoot
    $python = Join-Path $repo '.venv\Scripts\python.exe'
    if (Test-Path $python) { Push-Location $repo; try { & $python -m core.sandbox.build --remove; Say 'removed the parser sandbox' } finally { Pop-Location } }
    else { Say 'no Python environment here: the sandbox was not removed' }
}