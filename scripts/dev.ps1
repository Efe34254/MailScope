$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$EnginePython = Join-Path $Root "engine\.venv\Scripts\python.exe"
$EngineDir = Join-Path $Root "engine"

if (-not (Test-Path $EnginePython)) {
    throw "Python environment not found. Run .\scripts\setup.ps1 first."
}

$env:MAILSCOPE_ENGINE_CMD = $EnginePython
$env:MAILSCOPE_ENGINE_DIR = $EngineDir
Set-Location (Join-Path $Root "apps\desktop")
npm run tauri dev
