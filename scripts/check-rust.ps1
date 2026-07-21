. (Join-Path $PSScriptRoot 'common.ps1')

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Manifest = Join-Path $Root 'apps\desktop\src-tauri\Cargo.toml'
$Sidecar = Join-Path $Root 'apps\desktop\src-tauri\binaries\mailscope-engine.exe'
$CreatedPlaceholder = $false
$LocationPushed = $false

try {
    $Cargo = Assert-Command 'cargo.exe' 'Rust stable MSVC arac zincirini kurun.'
    New-Item -ItemType Directory -Path (Split-Path $Sidecar) -Force | Out-Null

    # Tauri validates configured resource paths during cargo check. The real
    # engine sidecar is produced by the application build and is not tracked.
    if (-not (Test-Path -LiteralPath $Sidecar -PathType Leaf)) {
        New-Item -ItemType File -Path $Sidecar | Out-Null
        $CreatedPlaceholder = $true
    }

    Push-Location $Root
    $LocationPushed = $true
    Invoke-Native $Cargo check --locked --manifest-path $Manifest
}
finally {
    if ($LocationPushed) { Pop-Location }
    if ($CreatedPlaceholder) {
        Remove-Item -LiteralPath $Sidecar -Force -ErrorAction SilentlyContinue
    }
}
