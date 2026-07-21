$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$ReleaseExe = Join-Path $Root "apps\desktop\src-tauri\target\release\mailscope.exe"

if (Test-Path $ReleaseExe) {
    Start-Process $ReleaseExe
    exit 0
}

Write-Host "Compiled MailScope was not found. Starting development mode..." -ForegroundColor Yellow
& (Join-Path $PSScriptRoot "dev.ps1")
