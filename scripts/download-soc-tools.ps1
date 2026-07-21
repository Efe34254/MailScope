$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ToolRoot = (Resolve-Path (Join-Path $Root 'engine\tools')).Path
$ManifestPath = Join-Path $ToolRoot 'manifest.json'
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$DownloadRoot = Join-Path $Root 'tmp\soc-tools-download'
$StageRoot = Join-Path $Root 'tmp\soc-tools-stage'

New-Item -ItemType Directory -Force -Path $DownloadRoot, $StageRoot | Out-Null

foreach ($Property in $Manifest.tools.PSObject.Properties) {
    $Name = $Property.Name
    $Definition = $Property.Value
    $ArchivePath = Join-Path $DownloadRoot $Definition.archive
    $StagePath = Join-Path $StageRoot $Name
    $Destination = Join-Path $ToolRoot $Name

    foreach ($Candidate in @($StagePath, $Destination)) {
        $FullCandidate = [IO.Path]::GetFullPath($Candidate)
        $ExpectedRoot = if ($Candidate -eq $StagePath) { [IO.Path]::GetFullPath($StageRoot) } else { [IO.Path]::GetFullPath($ToolRoot) }
        if (-not $FullCandidate.StartsWith($ExpectedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to replace path outside the expected tool directory: $FullCandidate"
        }
        if (Test-Path -LiteralPath $FullCandidate) {
            Remove-Item -LiteralPath $FullCandidate -Recurse -Force
        }
    }

    Write-Host "Downloading $Name $($Definition.version)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Definition.source -OutFile $ArchivePath -UseBasicParsing -UserAgent 'MailScope-Build/1.1.0'
    $ArchiveHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash
    if ($ArchiveHash -ne $Definition.archive_sha256) {
        throw "Archive SHA-256 verification failed for $Name. Expected $($Definition.archive_sha256), got $ArchiveHash"
    }

    New-Item -ItemType Directory -Force -Path $StagePath | Out-Null
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $StagePath -Force
    $ExecutableName = Split-Path $Definition.executable -Leaf
    $SourceExecutable = if ($Name -eq 'exiftool') {
        # The official Windows archive ships the interactive name
        # exiftool(-k).exe. MailScope uses the documented non-interactive
        # exiftool.exe name; renaming does not alter its pinned hash.
        Get-ChildItem -LiteralPath $StagePath -Filter 'exiftool(-k).exe' -File -Recurse |
            Select-Object -First 1
    } else {
        Get-ChildItem -LiteralPath $StagePath -Filter $ExecutableName -File -Recurse |
            Select-Object -First 1
    }
    if (-not $SourceExecutable) { throw "Downloaded archive does not contain $ExecutableName for $Name" }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -LiteralPath $SourceExecutable.FullName -Destination (Join-Path $Destination $ExecutableName) -Force
    if ($Name -eq 'exiftool') {
        $SupportDirectory = Join-Path $SourceExecutable.DirectoryName 'exiftool_files'
        if (-not (Test-Path -LiteralPath $SupportDirectory)) {
            throw 'Downloaded ExifTool package does not contain exiftool_files.'
        }
        Copy-Item -LiteralPath $SupportDirectory -Destination (Join-Path $Destination 'exiftool_files') -Recurse -Force
    }
}

& (Join-Path $PSScriptRoot 'verify-soc-tools.ps1')
Write-Host 'All pinned SOC tools were downloaded and verified.' -ForegroundColor Green
