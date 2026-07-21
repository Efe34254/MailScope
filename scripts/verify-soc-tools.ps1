$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ToolRoot = (Resolve-Path (Join-Path $Root 'engine\tools')).Path
$ManifestPath = Join-Path $ToolRoot 'manifest.json'
$Manifest = Get-Content -Raw $ManifestPath | ConvertFrom-Json
$VersionArguments = @{
    capa = @('--version')
    floss = @('--version')
    exiftool = @('-ver')
}

foreach ($Property in $Manifest.tools.PSObject.Properties) {
    $Name = $Property.Name
    $Definition = $Property.Value
    $Executable = (Resolve-Path (Join-Path $ToolRoot $Definition.executable)).Path
    if (-not $Executable.StartsWith($ToolRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Tool path escapes the bundle root: $Name"
    }
    $ActualHash = (Get-FileHash $Executable -Algorithm SHA256).Hash
    if ($ActualHash -ne $Definition.executable_sha256) {
        throw "SHA-256 verification failed for $Name. Expected $($Definition.executable_sha256), got $ActualHash"
    }
    if ($Name -eq 'exiftool' -and -not (Test-Path (Join-Path (Split-Path $Executable) 'exiftool_files'))) {
        throw 'ExifTool support directory is missing.'
    }

    Push-Location (Split-Path $Executable)
    try {
        $VersionOutput = (& $Executable @($VersionArguments[$Name]) 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "$Name self-test returned exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    Write-Host "Verified $Name $($Definition.version): $VersionOutput" -ForegroundColor Green
}
