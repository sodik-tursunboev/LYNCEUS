<#
.SYNOPSIS
  Make this checkout the Lynceus that runs for you, and prove it took. No administrator needed.

.DESCRIPTION
  Run it in a normal PowerShell window (Start menu, type "PowerShell"), not in a terminal inside another app:
  a terminal inside a packaged app writes to a private copy of the registry and Windows never sees it
  (ADR-024). The script checks that first and stops if so.

  It stops the running agent (this one and the one under the old name MIRAGE), rebuilds the parser sandbox
  from this checkout and registers it for you, registers start-at-logon and the browser bridge (removing
  what the old name registered), starts the agent, waits for the engine, and then asks Windows itself, not
  this shell, what is registered. Your data folder and your settings are not touched. Nothing is deleted.

.PARAMETER CheckOnly  Change nothing: only report what Windows has registered and what is running.
.PARAMETER CorePort   The engine's port. Default 8765.
#>
[CmdletBinding()]
param([switch]$CheckOnly, [int]$CorePort = 8765)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Acl.ps1')
. (Join-Path $PSScriptRoot 'RegistryView.ps1')
function Say($text) { Write-Host "[go-live] $text" }

$install = Join-Path $env:LOCALAPPDATA 'Programs\Lynceus'
$agentExe = Join-Path $install 'agent\Lynceus.Agent.exe'
$agentHome = if ($env:LYNCEUS_AGENT_HOME) { $env:LYNCEUS_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Lynceus' }
$agentConfig = Join-Path $agentHome 'agent.json'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$results = New-Object System.Collections.Generic.List[object]
function Check([string]$what, [bool]$ok, [string]$detail = '', [switch]$Advice) {
    $results.Add([pscustomobject]@{ What = $what; Ok = $ok; Detail = $detail; Advice = [bool]$Advice })
}
function Test-CoreUp { try { return (Invoke-WebRequest "http://127.0.0.1:$CorePort/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { return $false } }
function Get-EnvSetting([string]$name) {
    $file = Join-Path $repo '.env'
    if (-not (Test-Path $file)) { return $null }
    foreach ($prefix in 'LYNCEUS_', 'MIRAGE_') {
        $m = Select-String -Path $file -Pattern "^$prefix$name=(.*)$" | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
    }
    return $null
}

$script:private = $null
if (-not $CheckOnly) {
    if (-not ((Test-Path $agentExe) -and (Test-Path $python))) { throw "Lynceus is not installed from this checkout yet: run deploy\install.ps1 first." }
    $reaches = Test-RegistryReachesWindows
    $script:private = $reaches -eq $false
    if ($reaches -eq $false) {
        Write-Host ''
        Write-Host 'STOPPED: this window writes to a private copy of the registry, so nothing it registers would reach Windows.' -ForegroundColor Yellow
        Write-Host 'Open PowerShell from the Start menu (not a terminal inside another app) and run this again:'
        Write-Host "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit 2
    }
    if ($null -eq $reaches) { Write-Warning 'Could not check whether the registry is the real one (WMI did not answer). Carrying on; the checks at the end will tell.' }

    foreach ($name in 'Mirage.Agent', 'Lynceus.Agent') {
        foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) { Say "stopping $name ($($p.Id))"; & taskkill /PID $p.Id /T /F | Out-Null }
    }
    Start-Sleep -Seconds 2
    if (Test-CoreUp) { throw "something still answers on port $CorePort after the agents were stopped; stop it and run this again." }

    Push-Location $repo
    try {
        Say 'building the parser sandbox from this checkout and registering it for you'
        & $python tasks.py sandbox | Select-Object -Last 1 | ForEach-Object { Say $_ }
        if ($LASTEXITCODE) { throw 'tasks.py sandbox failed' }
        & $python -m core.sandbox.build --remove-legacy | Out-Null
    } finally { Pop-Location }

    Say 'registering start-at-logon and the browser bridge'
    & $agentExe --install

    # The agent starts the engine only if agent.json says how. Bring the old data folder along first (the
    # agent would do the same on start), then fill in the engine settings if they are missing.
    $legacyHome = Join-Path $env:LOCALAPPDATA 'Mirage'
    if (-not $env:LYNCEUS_AGENT_HOME -and -not (Test-Path $agentHome) -and (Test-Path $legacyHome)) {
        Move-Item -LiteralPath $legacyHome -Destination $agentHome
        Say "moved your data folder from $legacyHome to $agentHome"
    }
    if ((Set-AgentCoreConfig -ConfigPath $agentConfig -Python $python -WorkingDir $repo -Port $CorePort) -eq 'written') {
        Say "wrote the engine settings into $agentConfig (the agent starts the engine from $repo)"
    }
    Say 'starting the agent'
    Start-Process -FilePath $agentExe -WindowStyle Hidden
    $up = $false
    for ($i = 0; $i -lt 90 -and -not $up; $i++) { $up = Test-CoreUp; if (-not $up) { Start-Sleep -Seconds 1 } }
}

# ---- what Windows itself says (not this shell) -------------------------------------------------------------
$reg = Get-LynceusRegistration
Check 'starts at logon (Run: LynceusAgent)' ($reg.RunLynceus -and $reg.RunTarget -and (Test-IsUnder ($reg.RunTarget.Trim('"')) $install)) "$($reg.RunTarget)"
Check 'old start-at-logon entry (MirageAgent) is gone' (-not $reg.RunOldName)
Check 'browser bridge for Edge' $reg.EdgeBridge
Check 'browser bridge for Chrome' $reg.ChromeBridge
Check 'old browser bridges are gone' (-not ($reg.EdgeOldName -or $reg.ChromeOldName))
Check 'parser sandbox profile (lynceus.parser)' $reg.Sandbox
Check 'old sandbox profile (mirage.parser) is gone' (-not $reg.SandboxOld) '' -Advice
if ($null -eq $script:private) { $script:private = (Test-RegistryReachesWindows) -eq $false }
if ($script:private) {
    # This window sees private copies of AppData files too, so it cannot read the agent's real agent.json.
    Check 'the agent is set to start the engine (agent.json)' $false 'cannot be read from this window: it sees a private copy; run -CheckOnly from a normal PowerShell window' -Advice
} else {
    $engineCmd = $null
    try { if (Test-Path $agentConfig) { $engineCmd = (Get-Content $agentConfig -Raw | ConvertFrom-Json).CoreCommand } } catch { }
    Check 'the agent is set to start the engine (agent.json)' ([bool]($engineCmd -and (Test-Path $engineCmd))) "$agentConfig"
}
$running = @(Get-Process -Name 'Lynceus.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-IsUnder $_.Path $install) })
Check 'the Lynceus agent is running' ($running.Count -ge 1)
Check 'no agent under the old name is running' (@(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue).Count -eq 0)
Check "the engine answers on port $CorePort" (Test-CoreUp) "see $(Join-Path $agentHome 'agent.log') and core.log"
if ((Get-EnvSetting 'LLM_REVIEW') -match '^(1|true|yes|on)$') {
    $model = Get-EnvSetting 'LLM_MODEL'; if (-not $model) { $model = 'llama3.2:3b' }
    $names = @()
    try { $names = @((Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3).models | ForEach-Object { $_.name }) } catch { }
    Check "the local model ($model) is reachable for macro reviews" ($names -contains $model -or $names -contains "${model}:latest") 'start Ollama; until then macros are judged without the model (the verdict does not depend on it)' -Advice
}

Write-Host ''
Write-Host "  (this window: $(if ($script:private) { 'INSIDE a packaged app - registry and AppData are private copies here' } else { 'a normal window' }); run at $(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
foreach ($r in $results) {
    $mark = if ($r.Ok) { 'OK  ' } elseif ($r.Advice) { 'NOTE' } else { 'FAIL' }
    $color = if ($r.Ok) { 'Green' } elseif ($r.Advice) { 'Yellow' } else { 'Red' }
    $tail = if ($r.Detail -and -not $r.Ok) { "  ($($r.Detail))" } else { '' }
    Write-Host "  $mark $($r.What)$tail" -ForegroundColor $color
}
$failed = @($results | Where-Object { -not $_.Ok -and -not $_.Advice })
Write-Host ''
if ($failed.Count) {
    Write-Host "GO-LIVE: $($failed.Count) check(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host 'GO-LIVE OK: Windows has Lynceus registered and it is running.' -ForegroundColor Green
Say "Load the extension once: edge://extensions, Developer mode, Load unpacked: $(Join-Path $install 'extension') (remove the old MIRAGE one)"
foreach ($old in (Join-Path $env:LOCALAPPDATA 'Programs\Mirage'), (Join-Path $env:LOCALAPPDATA 'Mirage')) {
    if (Test-Path $old) { Say "left over from the old name, yours to delete when you like: $old" }
}
exit 0
