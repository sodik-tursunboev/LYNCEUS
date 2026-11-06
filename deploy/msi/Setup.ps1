<#
.SYNOPSIS  Runs once after the MSI has copied its files (per user, no administrator needed).
.DESCRIPTION
  Registers the parser sandbox for this user (the MSI ships it built), writes agent.json and a first
  engine\.env if there are none, applies database migrations if a database is configured, registers
  start-at-logon and the browser bridge, and starts the agent. Your data folder is never touched. A
  failure here makes the installer roll back; the reason is in %LOCALAPPDATA%\Mirage\setup.log.
.PARAMETER InstallDir   The folder the MSI installed to.
.PARAMETER NoStart      Anything but empty or 0: do not start the agent.
.PARAMETER NoRegister   Anything but empty or 0: do not register start-at-logon and the browser bridge.
.PARAMETER ResetConfig  Anything but empty or 0: point agent.json at this install even if it points elsewhere.
.PARAMETER CorePort     The core's port. Default 8765.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InstallDir,
    [string]$NoStart = '',
    [string]$NoRegister = '',
    [string]$ResetConfig = '',
    [int]$CorePort = 8765
)
$ErrorActionPreference = 'Stop'
# the installer passes 0 for "not set" (an empty argument can be lost on the way)
function IsOn($value) { [bool]($value -and $value -ne '0') }
$skipStart = IsOn $NoStart
$skipRegister = IsOn $NoRegister
$forceConfig = IsOn $ResetConfig
$install = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
$engine = Join-Path $install 'engine'
$python = Join-Path $engine 'python\python.exe'
$agentExe = Join-Path $install 'agent\Mirage.Agent.exe'
$home_ = if ($env:MIRAGE_AGENT_HOME) { $env:MIRAGE_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Mirage' }
New-Item -ItemType Directory -Force $home_ | Out-Null
$log = Join-Path $home_ 'setup.log'
function Say($text) { Add-Content -Path $log -Value "$(Get-Date -Format s) $text"; Write-Host "[setup] $text" }
function Test-IsUnder($path, $folder) {
    $p = [System.IO.Path]::GetFullPath($path).TrimEnd('\') + '\'
    $f = [System.IO.Path]::GetFullPath($folder).TrimEnd('\') + '\'
    $p.StartsWith($f, [System.StringComparison]::OrdinalIgnoreCase)
}

try {
    if (-not ((Test-Path $python) -and (Test-Path $agentExe))) { throw "$install does not look like a MIRAGE install" }

    # ---- the sandbox: shipped built, registered for this user -------------------------------------
    Say 'registering the parser sandbox for this user'
    Push-Location $engine
    try {
        $out = & $python -E -s -m core.sandbox.build --register 2>&1
        if ($LASTEXITCODE) { throw "the sandbox could not be registered: $($out -join ' ')" }
        Say ($out -join ' ')
    } finally { Pop-Location }

    # ---- configuration (your settings are kept) ------------------------------------------------------
    $config = Join-Path $home_ 'agent.json'
    $cfg = if (Test-Path $config) { Get-Content $config -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
    $oursOrNew = (-not $cfg.CoreWorkingDir) -or (Test-IsUnder $cfg.CoreWorkingDir $install)
    if ($oursOrNew -or $forceConfig) {
        if (Test-Path $config) { Copy-Item $config "$config.bak" -Force }
        $values = [ordered]@{
            CoreUrl        = "http://127.0.0.1:$CorePort"
            CoreCommand    = $python
            CoreWorkingDir = $engine
            # -E and -s: ignore PYTHON* variables and the user's own site-packages
            CoreArgs       = @('-E', '-s', '-m', 'uvicorn', 'core.api.app:create_app', '--factory', '--host', '127.0.0.1', '--port', "$CorePort", '--no-access-log', '--no-server-header')
        }
        foreach ($k in $values.Keys) { $cfg | Add-Member -NotePropertyName $k -NotePropertyValue $values[$k] -Force }
        [System.IO.File]::WriteAllText($config, ($cfg | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
        Say "wrote $config"
    } else {
        Say "kept your $config, which runs the core from $($cfg.CoreWorkingDir) (add ResetConfig=1 to the install to use this one)"
    }

    $envFile = Join-Path $engine '.env'
    if (-not (Test-Path $envFile)) {
        $example = 'postgresql+psycopg://USER:' + 'PASSWORD@127.0.0.1:5432/mirage'
        $text = "MIRAGE_DATA_DIR=$(Join-Path $home_ 'data')`r`n# Responses and the console lists need a PostgreSQL database:`r`n# MIRAGE_DATABASE_URL=$example`r`n"
        [System.IO.File]::WriteAllText($envFile, $text, (New-Object System.Text.UTF8Encoding($false)))
        Say "wrote $envFile"
    }

    # ---- database (only if you configured one) --------------------------------------------------------
    $url = $null
    $m = Select-String -Path $envFile -Pattern '^MIRAGE_DATABASE_URL=(.+)$' | Select-Object -First 1
    if ($m) { $url = $m.Matches[0].Groups[1].Value }
    if ($url) {
        Say 'applying database migrations'
        $env:MIRAGE_DATABASE_URL = $url
        Push-Location $engine
        try { $out = & $python -E -s -m alembic upgrade head 2>&1; Say (($out | Select-Object -Last 2) -join ' ') } finally { Pop-Location; Remove-Item Env:\MIRAGE_DATABASE_URL -ErrorAction SilentlyContinue }
    } else { Say "no MIRAGE_DATABASE_URL in ${envFile}: skipping migrations (responses and the console lists need a database)" }

    # ---- register and start -----------------------------------------------------------------------------
    if (-not $skipRegister) {
        Say 'registering start-at-logon and the browser bridge'
        & $agentExe --install
        $status = (& $agentExe --status) -join ' '
        if ($status -match 'False') {   # seen once: the Edge entry missing after the first call, present after a second
            Say "registration incomplete ($status); trying once more"
            Start-Sleep -Seconds 2; & $agentExe --install
            $status = (& $agentExe --status) -join ' '
        }
        if ($status -match 'False') { Say ('WARNING: registration still incomplete (' + $status + '). Run "' + $agentExe + '" --install') } else { Say $status }
    }
    if (-not $skipStart) {
        $elsewhere = @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and -not (Test-IsUnder $_.Path $install) })
        if ($elsewhere.Count) {
            Say "a MIRAGE agent is already running from $($elsewhere[0].Path), so this one was not started. Stop that one and start $agentExe."
        } else {
            Say 'starting the agent'
            Start-Process -FilePath $agentExe -WindowStyle Hidden
            $up = $false
            for ($i = 0; $i -lt 60 -and -not $up; $i++) {
                try { $up = (Invoke-WebRequest "http://127.0.0.1:$CorePort/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep -Seconds 1 }
            }
            if ($up) { Say "the core answers on port $CorePort" } else { Say "WARNING: the core did not answer on port $CorePort within 60 seconds; see $(Join-Path $home_ 'agent.log') and core.log" }
        }
    }
    Say 'done.'
} catch {
    Say "FAILED: $($_.Exception.Message)"
    exit 1
}
