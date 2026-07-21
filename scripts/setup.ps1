. (Join-Path $PSScriptRoot 'common.ps1')
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Engine = Join-Path $Root 'engine'
$Desktop = Join-Path $Root 'apps\desktop'

Write-Host '[1/5] Python 3.13 kontrol ediliyor...' -ForegroundColor Cyan
$Python = Ensure-Python313
$Version = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
Write-Host "Kullanilan Python: $Version ($Python)" -ForegroundColor Green

$Venv = Join-Path $Engine '.venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'
if (Test-Path $VenvPython) {
    $VenvMinor = & $VenvPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
    if ($LASTEXITCODE -ne 0 -or $VenvMinor.Trim() -ne '3.13') {
        Write-Host 'Eski veya uyumsuz sanal ortam siliniyor...' -ForegroundColor Yellow
        Remove-Item $Venv -Recurse -Force
    }
}

Write-Host '[2/5] Sabitlenmis SOC araclari indiriliyor ve dogrulaniyor...' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'download-soc-tools.ps1')

Write-Host '[3/5] Python motoru hazirlaniyor...' -ForegroundColor Cyan
Set-Location $Engine
if (-not (Test-Path $VenvPython)) {
    Invoke-Native $Python -m venv .venv
}
Invoke-Native $VenvPython -m pip install --upgrade pip setuptools wheel
Invoke-Native $VenvPython -m pip install -r requirements.txt
Invoke-Native $VenvPython -m pytest -q

Write-Host '[4/5] Node.js kontrol ediliyor...' -ForegroundColor Cyan
$Npm = Assert-Command 'npm.cmd' 'Node.js 22 LTS 22.12.0 veya daha yeni bir surum kurun.'
$Node = Assert-Command 'node.exe' 'Node.js 22 LTS 22.12.0 veya daha yeni bir surum kurun.'
$NodeVersionText = (& $Node --version).Trim().TrimStart('v')
try {
    $NodeVersion = [version]$NodeVersionText
} catch {
    throw "Node.js surumu okunamadi: $NodeVersionText"
}
$MinimumNodeVersion = [version]'22.12.0'
if ($NodeVersion -lt $MinimumNodeVersion) {
    throw "Node.js $MinimumNodeVersion veya daha yeni bir surum gerekli. Bulunan surum: $NodeVersion"
}

Write-Host '[5/5] Masaustu bagimliliklari kuruluyor...' -ForegroundColor Cyan
Set-Location $Desktop
if (Test-Path 'package-lock.json') {
    Invoke-Native $Npm ci
} else {
    Invoke-Native $Npm install
}
Write-Host 'Hazirlik tamamlandi.' -ForegroundColor Green
