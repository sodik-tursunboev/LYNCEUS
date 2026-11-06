<#
.SYNOPSIS
  Turn a clean checkout into a running MIRAGE install for the current user (no administrator needed).

.DESCRIPTION
  Builds the agent (framework-dependent publish), the browser extension and the console, copies the agent and the
  extension to a stable folder, writes agent.json if there is none, registers start-at-logon and the browser bridge,
  starts the agent and waits until the core answers. Running it again is an upgrade: the agent is stopped, its files
  are replaced, your data folder (%LOCALAPPDATA%\Mirage, or MIRAGE_AGENT_HOME) is never touched, and the agent is
  started again. The core itself runs from this checkout (its Python environment, the sandbox and the console), so
  keep the checkout where it is, or run this script again after moving it.

.PARAMETER InstallDir   Where the agent and the extension go. Default: %LOCALAPPDATA%\Programs\Mirage
.PARAMETER CorePort     The core's port. Default 8765.
.PARAMETER NoRegister   Do not touch the registry (start-at-logon, browser bridge). Used by the automated test.
.PARAMETER NoStart      Do not start the agent afterwards.
.PARAMETER ResetConfig  Write agent.json even if one exists (the old one is kept as agent.json.bak).
.PARAMETER SkipMigrate  Do not run database migrations.
.PARAMETER HardenAcl    Restrict this checkout (which the core runs from) to you, SYSTEM and Administrators. Only needed when
                        the script warns that other accounts can change it; the folder's permissions are rewritten.
.PARAMETER Force        Install into a folder that already holds something that is not a MIRAGE install.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Mirage'),
    [int]$CorePort = 8765,
    [switch]$NoRegister,
    [switch]$NoStart,
    [switch]$ResetConfig,
    [switch]$SkipMigrate,
    [switch]$HardenAcl,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Acl.ps1')
function Say($text) { Write-Host "[install] $text" }
function Need($name) { if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name is required and was not found on PATH." } }

Need dotnet; Need node; Need npm
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Need python
    Say 'creating the Python environment (hash-pinned parser libraries; this takes a minute)'
    Push-Location $repo
    try { python -m venv .venv; & $python tasks.py deps; if ($LASTEXITCODE) { throw 'tasks.py deps failed' } } finally { Pop-Location }
}
Push-Location $repo
try {
    if (-not (Test-Path (Join-Path $repo '.sandbox'))) {
        Say 'building the parser sandbox'
        & $python tasks.py sandbox; if ($LASTEXITCODE) { throw 'tasks.py sandbox failed' }
    }
} finally { Pop-Location }

# ---- is the target sensible, and who can change what the core runs? -------------------------------------
$installFull = [System.IO.Path]::GetFullPath($InstallDir)
$profileRoot = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
if ($installFull.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($installFull).TrimEnd('\') -or $installFull.TrimEnd('\') -eq $profileRoot) {
    throw "refusing to install into $installFull (a drive root or your profile folder): name a folder of its own"
}
if ((Test-Path -LiteralPath $installFull) -and (Get-ChildItem -LiteralPath $installFull -Force | Select-Object -First 1) -and -not (Test-MirageInstall $installFull) -and -not $Force) {
    throw "$installFull is not empty and is not a MIRAGE install. Choose another folder, or add -Force."
}
$others = @(Get-ChangeableByOthers $repo)
if ($others.Count -and $HardenAcl) {
    Say "restricting $repo to you, SYSTEM and Administrators (it was changeable by: $($others -join ', '))"
    Protect-Folder $repo
    Push-Location $repo
    try { & $python tasks.py sandbox; if ($LASTEXITCODE) { throw 'tasks.py sandbox failed after the permission change' } } finally { Pop-Location }
} elseif ($others.Count) {
    Write-Warning ("Other accounts on this computer can change $repo ($($others -join ', ')). The core runs from this folder with YOUR rights and your API token, " +
        "so anyone who can edit it can run code as you. On a computer only you use this does not matter; otherwise run this script again with -HardenAcl.")
}

# ---- stop what is running from the install folder (an upgrade) ----------------------------------------
$stopped = @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and (Test-IsUnder $_.Path $installFull) })
foreach ($p in $stopped) { Say "stopping the running agent ($($p.Id))"; & taskkill /PID $p.Id /T /F | Out-Null }
if ($stopped.Count) { Start-Sleep -Seconds 2 }

# ---- build ----------------------------------------------------------------------------------------------
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("mirage-publish-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
Say 'building the agent'
dotnet publish (Join-Path $repo 'agent\Mirage.Agent\Mirage.Agent.csproj') -c Release -o (Join-Path $stage 'agent') --nologo -v quiet
if ($LASTEXITCODE) { throw 'dotnet publish failed' }
foreach ($exe in 'Mirage.Agent.exe', 'Mirage.NativeHost.exe') {
    if (-not (Test-Path (Join-Path $stage "agent\$exe"))) { throw "the publish did not produce $exe" }
}
foreach ($app in 'extension', 'console') {
    Say "building the $app"
    Push-Location (Join-Path $repo $app)
    try {
        if (-not (Test-Path 'node_modules')) { npm ci --ignore-scripts --no-audit --no-fund | Out-Null; if ($LASTEXITCODE) { throw "npm ci failed in $app" } }
        node build.mjs | Out-Null; if ($LASTEXITCODE) { throw "build failed in $app" }
    } finally { Pop-Location }
}

# ---- copy ------------------------------------------------------------------------------------------------
Say "installing to $installFull"
New-Item -ItemType Directory -Force (Join-Path $installFull 'agent'), (Join-Path $installFull 'extension') | Out-Null
Copy-Item (Join-Path $stage 'agent\*') (Join-Path $installFull 'agent') -Recurse -Force
Remove-Item (Join-Path $installFull 'extension\*') -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $repo 'extension\dist\*') (Join-Path $installFull 'extension') -Recurse -Force
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
$agentExe = Join-Path $installFull 'agent\Mirage.Agent.exe'

# ---- configuration (never overwrites yours unless asked) ---------------------------------------------------
$home_ = if ($env:MIRAGE_AGENT_HOME) { $env:MIRAGE_AGENT_HOME } else { Join-Path $env:LOCALAPPDATA 'Mirage' }
New-Item -ItemType Directory -Force $home_ | Out-Null
$config = Join-Path $home_ 'agent.json'
if ((-not (Test-Path $config)) -or $ResetConfig) {
    if (Test-Path $config) { Copy-Item $config "$config.bak" -Force }
    $settings = [ordered]@{
        CoreUrl        = "http://127.0.0.1:$CorePort"
        CoreCommand    = $python
        CoreWorkingDir = $repo
        CoreArgs       = @('-m', 'uvicorn', 'core.api.app:create_app', '--factory', '--host', '127.0.0.1', '--port', "$CorePort", '--no-access-log', '--no-server-header')
    }
    [System.IO.File]::WriteAllText($config, ($settings | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    Say "wrote $config"
} else { Say "kept your $config" }

# ---- database ------------------------------------------------------------------------------------------------
if (-not $SkipMigrate) {
    $envFile = Join-Path $repo '.env'
    $url = $null
    if (Test-Path $envFile) { $m = Select-String -Path $envFile -Pattern '^MIRAGE_DATABASE_URL=(.+)$' | Select-Object -First 1; if ($m) { $url = $m.Matches[0].Groups[1].Value } }
    if ($url) {
        Say 'applying database migrations'
        $env:MIRAGE_DATABASE_URL = $url
        Push-Location $repo
        try { & $python -m alembic upgrade head 2>&1 | Select-Object -Last 2 | ForEach-Object { Say $_ } } finally { Pop-Location; Remove-Item Env:\MIRAGE_DATABASE_URL -ErrorAction SilentlyContinue }
    } else { Say 'no MIRAGE_DATABASE_URL in .env: skipping migrations (responses and the console lists need a database)' }
}

# ---- register -----------------------------------------------------------------------------------------------
if (-not $NoRegister) { Say 'registering start-at-logon and the browser bridge'; & $agentExe --install; Start-Sleep -Milliseconds 500 }

# ---- start and wait -----------------------------------------------------------------------------------------
if (-not $NoStart) {
    Say 'starting the agent'
    $elsewhere = @(Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and -not (Test-IsUnder $_.Path $installFull) })
    if ($elsewhere.Count) {
        throw "a MIRAGE agent is already running from $($elsewhere[0].Path). Only one agent can run at a time, and it is not this install: stop it (or run its uninstaller) and run this script again."
    }
    Start-Process -FilePath $agentExe -WindowStyle Hidden
    $up = $false
    for ($i = 0; $i -lt 90 -and -not $up; $i++) {
        try { $up = (Invoke-WebRequest "http://127.0.0.1:$CorePort/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $up) { throw "the core did not answer on port $CorePort within 90 seconds; see $(Join-Path $home_ 'agent.log') and core.log" }
    if (-not (Get-Process -Name 'Mirage.Agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -and (Test-IsUnder $_.Path $installFull) })) {
        throw "the core answers on port $CorePort, but no agent is running from ${installFull}: something else is serving that port"
    }
    Say "the core answers on port $CorePort"
}
Say 'done.'
Say "Load the extension: edge://extensions, Developer mode, Load unpacked: $(Join-Path $installFull 'extension')"
Say "Open the console:   & '$agentExe' --open-console"