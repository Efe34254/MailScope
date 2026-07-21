. (Join-Path $PSScriptRoot 'common.ps1')
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')

try {
    Write-Host 'MailScope Build System v3 baslatildi.' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'setup.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Hazirlik asamasi basarisiz oldu.' }

    $Installer = & (Join-Path $PSScriptRoot 'build.ps1') | Select-Object -Last 1
    if (-not $Installer -or -not (Test-Path $Installer)) { throw 'Installer yolu alinamadi.' }

    Write-Host ''
    Write-Host 'DERLEME BASARILI' -ForegroundColor Green
    Write-Host "Installer: $Installer" -ForegroundColor Green
    Write-Host 'Kurulum dosyasi aciliyor...' -ForegroundColor Cyan
    Start-Process -FilePath $Installer
} catch {
    Write-Host ''
    Write-Host 'DERLEME BASARISIZ' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ''
    Write-Host 'Bu pencerenin ekran goruntusunu veya build-log.txt dosyasini paylasabilirsiniz.' -ForegroundColor Yellow
    throw
}
