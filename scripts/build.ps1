. (Join-Path $PSScriptRoot 'common.ps1')
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Engine = Join-Path $Root 'engine'
$Desktop = Join-Path $Root 'apps\desktop'
$BinaryDir = Join-Path $Desktop 'src-tauri\binaries'
$TargetRelease = Join-Path $Desktop 'src-tauri\target\release'
$Output = Join-Path $Root 'output'
$VenvPython = Join-Path $Engine '.venv\Scripts\python.exe'
$Version = '1.1.0'
$SignScript = Join-Path $Root 'scripts\sign-release.ps1'
$SigningEnabled = -not [string]::IsNullOrWhiteSpace($env:MAILSCOPE_SIGN_CERT_THUMBPRINT)

if (-not (Test-Path $VenvPython)) { throw 'Python ortami bulunamadi. Once scripts\setup.ps1 calistirin.' }
& (Join-Path $Root 'scripts\verify-soc-tools.ps1')
$Minor = & $VenvPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($Minor.Trim() -ne '3.13') { throw "Uyumsuz Python ortami: $Minor. .venv klasorunu silip kurulumu yeniden calistirin." }

Write-Host '[1/4] Python analiz motoru EXE olarak paketleniyor...' -ForegroundColor Cyan
Set-Location $Engine
Remove-Item '.\build', '.\dist' -Recurse -Force -ErrorAction SilentlyContinue
Invoke-Native $VenvPython -m PyInstaller --clean --noconfirm mailscope_engine.spec
$EngineExe = Join-Path $Engine 'dist\mailscope-engine.exe'
if (-not (Test-Path $EngineExe)) { throw "Python motoru olusturulamadi: $EngineExe" }
if ($SigningEnabled) { & $SignScript -Path $EngineExe }
New-Item -ItemType Directory -Force -Path $BinaryDir | Out-Null
Copy-Item $EngineExe (Join-Path $BinaryDir 'mailscope-engine.exe') -Force

Write-Host '[2/4] Tauri CLI ve Windows derleme ortami kontrol ediliyor...' -ForegroundColor Cyan
Assert-Command 'cargo.exe' 'Rust kurulu degil. https://rustup.rs uzerinden Rust kurun.' | Out-Null
$TauriCmd = Join-Path $Desktop 'node_modules\.bin\tauri.cmd'
if (-not (Test-Path $TauriCmd)) {
    throw "Yerel Tauri CLI bulunamadi: $TauriCmd. Once scripts\setup.ps1 calistirin."
}
Set-Location $Desktop
Invoke-Native $TauriCmd --version

Write-Host '[3/4] Tauri Windows uygulamasi ve NSIS installer derleniyor...' -ForegroundColor Cyan
# Imzali dagitimda once uygulama uretilip imzalanir, sonra installer bu imzali
# uygulamadan olusturulur. Boylece yalniz installer degil kurulan EXE de imzalidir.
if ($SigningEnabled) {
    Invoke-Native $TauriCmd build --no-bundle
    $UnsignedAppExe = Get-ChildItem -Path $TargetRelease -Filter '*.exe' -File |
        Where-Object { $_.DirectoryName -eq $TargetRelease } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $UnsignedAppExe) { throw "Tauri uygulama EXE'si bulunamadi: $TargetRelease" }
    & $SignScript -Path $UnsignedAppExe.FullName
    Invoke-Native $TauriCmd bundle --bundles nsis
} else {
    Invoke-Native $TauriCmd build --bundles nsis
}

Write-Host '[4/4] Release dosyalari hazirlaniyor...' -ForegroundColor Cyan
$Bundle = Join-Path $TargetRelease 'bundle\nsis'
$Installer = Get-ChildItem -Path $Bundle -Filter '*.exe' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Installer) { throw "NSIS installer bulunamadi: $Bundle" }
if ($SigningEnabled) { & $SignScript -Path $Installer.FullName }

New-Item -ItemType Directory -Force -Path $Output | Out-Null
$Destination = Join-Path $Output "MailScope_Setup_$Version.exe"
Copy-Item $Installer.FullName $Destination -Force

# Portable paket: ana exe ve Tauri'nin release kaynaklari birlikte saklanir.
$PortableDir = Join-Path $Output "MailScope_Portable_$Version"
Remove-Item $PortableDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $PortableDir | Out-Null
$AppExe = Get-ChildItem -Path $TargetRelease -Filter '*.exe' -File |
    Where-Object { $_.DirectoryName -eq $TargetRelease } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($AppExe) {
    Copy-Item $AppExe.FullName (Join-Path $PortableDir 'MailScope.exe') -Force
}
$ReleaseBinaries = Join-Path $TargetRelease 'binaries'
if (Test-Path $ReleaseBinaries) { Copy-Item $ReleaseBinaries (Join-Path $PortableDir 'binaries') -Recurse -Force }
elseif (Test-Path $BinaryDir) { Copy-Item $BinaryDir (Join-Path $PortableDir 'binaries') -Recurse -Force }
$PortableZip = Join-Path $Output "MailScope_Portable_$Version.zip"
Remove-Item $PortableZip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $PortableDir '*') -DestinationPath $PortableZip -CompressionLevel Optimal
Remove-Item $PortableDir -Recurse -Force

$InstallerHash = (Get-FileHash $Destination -Algorithm SHA256).Hash
$PortableHash = (Get-FileHash $PortableZip -Algorithm SHA256).Hash
@(
    "$InstallerHash  $(Split-Path $Destination -Leaf)",
    "$PortableHash  $(Split-Path $PortableZip -Leaf)"
) | Set-Content (Join-Path $Output 'SHA256SUMS.txt') -Encoding ASCII

$InstallerSignature = (Get-AuthenticodeSignature -LiteralPath $Destination).Status.ToString()
$PortableAppSignature = if ($AppExe) { (Get-AuthenticodeSignature -LiteralPath $AppExe.FullName).Status.ToString() } else { 'Missing' }
$ReleaseManifest = [ordered]@{
    format = 'mailscope-release-v1'
    version = $Version
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    installer = [ordered]@{ file = (Split-Path $Destination -Leaf); sha256 = $InstallerHash; authenticode = $InstallerSignature }
    portable = [ordered]@{ file = (Split-Path $PortableZip -Leaf); sha256 = $PortableHash; application_authenticode = $PortableAppSignature }
    signing_required_for_distribution = $true
}
$ReleaseManifest | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Output 'release-manifest.json') -Encoding UTF8

if (-not $SigningEnabled) {
    Write-Warning 'Release is unsigned. Configure MAILSCOPE_SIGN_CERT_THUMBPRINT before distributing outside this device.'
}

Write-Host "Installer hazir: $Destination" -ForegroundColor Green
Write-Host "Portable ZIP hazir: $PortableZip" -ForegroundColor Green
Write-Host "Checksum: $(Join-Path $Output 'SHA256SUMS.txt')" -ForegroundColor Green
Write-Host "Release manifest: $(Join-Path $Output 'release-manifest.json')" -ForegroundColor Green
Write-Output $Destination
