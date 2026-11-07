<#
.SYNOPSIS  Build deploy\msi\out\Lynceus-<version>-x64.msi from this checkout.
.DESCRIPTION
  Stages the self-contained agent (no .NET needed on the target), the browser extension, the native
  console window (Tauri; needs Rust, see shell\), and the engine (a trimmed Python with only the libraries the core needs, the core, the console and the
  already built sandbox), then runs WiX. Needs: dotnet SDK, node/npm, this checkout's .venv with a
  current .sandbox (python tasks.py sandbox), and the WiX tool (dotnet tool install --global wix
  --version 5.0.2; WiX 7 asks you to accept a fee EULA first, 5.0.2 does not).
.PARAMETER Version  Three numbers, e.g. 0.1.0. A higher number upgrades a lower one.
#>
[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [switch]$KeepStage,   # leave the staged files after the build, so ...
    [switch]$ReuseStage   # ... another version can be built from them without staging again
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$stage = Join-Path $PSScriptRoot 'stage\payload'
$outDir = Join-Path $PSScriptRoot 'out'
function Say($text) { Write-Host "[msi] $text" }
function Need($name) { if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "$name is required and was not found on PATH." } }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Version must be three numbers, like 0.1.0' }
$env:PATH += ";$env:USERPROFILE\.dotnet\tools"
$env:DOTNET_ROLL_FORWARD = 'LatestMajor'
Need dotnet; Need node; Need npm; Need wix
$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { throw 'no .venv here: run python tasks.py deps' }

if ($ReuseStage -and -not (Test-Path (Join-Path $stage 'engine'))) { throw 'nothing to reuse: build once with -KeepStage first' }
if (-not $ReuseStage) {
if (Test-Path $stage) { Remove-Item (Split-Path $stage) -Recurse -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Say 'building the agent (self-contained)'
dotnet publish (Join-Path $repo 'agent\Lynceus.Agent\Lynceus.Agent.csproj') -c Release -r win-x64 --self-contained true -o (Join-Path $stage 'agent') --nologo -v quiet
if ($LASTEXITCODE) { throw 'dotnet publish failed' }
foreach ($exe in 'Lynceus.Agent.exe', 'Lynceus.NativeHost.exe') {
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
Copy-Item (Join-Path $repo 'extension\dist') (Join-Path $stage 'extension') -Recurse

Say 'building the native console window (Tauri; the first build compiles for several minutes)'
$env:PATH += ";$env:USERPROFILE\.cargo\bin"
Need cargo
Push-Location (Join-Path $repo 'shell')
$strict = $ErrorActionPreference
$ErrorActionPreference = 'Continue'   # Tauri and npm write progress to stderr; the exit code is what counts
try {
    if (-not (Test-Path 'node_modules')) { npm ci --ignore-scripts --no-audit --no-fund 2>&1 | Out-Null; if ($LASTEXITCODE) { throw 'npm ci failed in shell' } }
    npx tauri build --no-bundle 2>&1 | Out-Null; if ($LASTEXITCODE) { throw 'the Tauri build failed' }
} finally { $ErrorActionPreference = $strict; Pop-Location }
New-Item -ItemType Directory -Force (Join-Path $stage 'shell') | Out-Null
Copy-Item (Join-Path $repo 'shell\src-tauri\target\release\lynceus-console.exe') (Join-Path $stage 'shell\Lynceus.Console.exe')

Say 'staging the engine (Python, core, console, sandbox)'
& $python (Join-Path $PSScriptRoot 'stage_engine.py') (Join-Path $stage 'engine') | Select-Object -Last 2
if ($LASTEXITCODE) { throw 'staging the engine failed' }
}   # (not reusing a stage)
Copy-Item (Join-Path $PSScriptRoot 'Setup.ps1'), (Join-Path $PSScriptRoot 'Cleanup.ps1') $stage -Force
New-Item -ItemType Directory -Force $outDir | Out-Null

$msi = Join-Path $outDir "Lynceus-$Version-x64.msi"
Say "building $msi"
wix build (Join-Path $PSScriptRoot 'Lynceus.wxs') -arch x64 -d "Version=$Version" -d "StageDir=$stage" -dcl mszip -o $msi
if ($LASTEXITCODE) { throw 'wix build failed' }
if (-not ($KeepStage -or $ReuseStage)) { Remove-Item (Split-Path $stage) -Recurse -Force }
Say ("done: {0} ({1:N0} MB)" -f $msi, ((Get-Item $msi).Length / 1MB))
