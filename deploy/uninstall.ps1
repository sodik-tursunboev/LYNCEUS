<#
.SYNOPSIS  Remove what install.ps1 added. Your data (quarantine, logs, spool) stays unless you ask.
.PARAMETER InstallDir   The folder install.ps1 used. Default: %LOCALAPPDATA%\Programs\Mirage
.PARAMETER NoRegister   Do not touch the registry.
.PARAMETER RemoveData   Also delete the data folder, INCLUDING THE QUARANTINE FOLDER: files in it are gone for good.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Mirage'),
    [switch]$NoRegister,
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
function Say($text) { Write-Host "[uninstall] $text" }
$installFull = [System.IO.Path]::GetFullPath($InstallDir)
$agentExe = Join-Path $installFull 'agent\Mirage.Agent.exe'
foreach ($p in @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($installFull, [System.StringComparison]::OrdinalIgnoreCase) })) {
    Say "stopping the agent ($($p.Id))"; & taskkill /PID $p.Id /T /F | Out-Null
}
Start-Sleep -Seconds 2
if ((-not $NoRegister) -and (Test-Path $agentExe)) { Say 'removing start-at-logon and the browser bridge'; & $agentExe --uninstall }
if (Test-Path $installFull) { Remove-Item $installFull -Recurse -Force; Say "removed $installFull" }
$home_ = if ($env:MIRAGE_AGENT_HOME) { $env:MIRAGE_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Mirage' }
if ($RemoveData) {
    if (Test-Path $home_) { Remove-Item $home_ -Recurse -Force; Say "removed the data folder $home_ (quarantined files included)" }
} else {
    Say "kept your data in $home_ (logs, spool, token, quarantine). Delete it yourself, or run again with -RemoveData."
}