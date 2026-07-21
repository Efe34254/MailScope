Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Native {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments
    )

    # Many native build tools (PyInstaller, Cargo and NSIS) write ordinary
    # progress messages to stderr. Windows PowerShell converts those lines to
    # ErrorRecord objects. With ErrorActionPreference=Stop this can terminate a
    # successful command after its first informational line. Temporarily allow
    # native stderr, preserve all output, and decide success only by exit code.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments 2>&1 | ForEach-Object {
            Write-Host $_
        }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    if ($exitCode -ne 0) {
        throw "Command failed ($exitCode): $FilePath $($Arguments -join ' ')"
    }
}

function Find-Python313 {
    $candidates = @()

    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) {
        try {
            $resolved = & $py.Source -3.13 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved) { $candidates += $resolved.Trim() }
        } catch {}
    }

    foreach ($name in @('python3.13.exe', 'python.exe')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            try {
                $version = & $cmd.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
                if ($LASTEXITCODE -eq 0 -and $version.Trim() -eq '3.13') { $candidates += $cmd.Source }
            } catch {}
        }
    }

    $known = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:ProgramFiles\Python313\python.exe"
    )
    foreach ($path in $known) {
        if (Test-Path $path) { $candidates += $path }
    }

    return $candidates | Select-Object -First 1
}

function Ensure-Python313 {
    $python = Find-Python313
    if ($python) { return $python }

    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw @"
Python 3.13 bulunamadi ve Winget kullanilamiyor.
Python 3.13 x64 kurup Build-MailScope.cmd dosyasini yeniden calistirin.
Python 3.14 bu proje icin kullanilmayacaktir.
"@
    }

    Write-Host 'Python 3.13 bulunamadi. Winget ile kuruluyor...' -ForegroundColor Yellow
    Invoke-Native $winget.Source install --id Python.Python.3.13 --exact --scope user --accept-package-agreements --accept-source-agreements --silent

    $python = Find-Python313
    if (-not $python) {
        throw 'Python 3.13 kuruldu ancak bu oturumda bulunamadi. PowerShell penceresini kapatip Build-MailScope.cmd dosyasini yeniden calistirin.'
    }
    return $python
}

function Assert-Command {
    param([Parameter(Mandatory=$true)][string]$Name, [string]$Help)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "$Name bulunamadi. $Help" }
    return $cmd.Source
}
