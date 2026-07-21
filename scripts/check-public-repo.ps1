Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $root
try {
    $tracked = @(& git ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed.' }

    $failures = New-Object System.Collections.Generic.List[string]
    $blockedPathPattern = '(?i)(^|/)(\.env($|\.)|[^/]+\.(eml|db|db-wal|db-shm|msbackup|pfx|p12|pem|key)$)'
    $blockedDirectoryPattern = '(?i)(^|/)(node_modules|target|dist|build|output|backups|tmp|\.venv|engine/workspace)(/|$)'

    foreach ($path in $tracked) {
        $normalized = $path -replace '\\', '/'
        if ($normalized -match $blockedPathPattern) {
            $failures.Add("Blocked sensitive file type is tracked: $normalized")
        }
        if ($normalized -match $blockedDirectoryPattern) {
            $failures.Add("Generated or private directory is tracked: $normalized")
        }
    }

    $contentPatterns = @(
        @{ Name = 'absolute workstation path'; Pattern = '(?i)([A-Z]:\\Users\\[^\\\s]+\\|/home/[^/\s]+/|/Users/[^/\s]+/)' },
        @{ Name = 'internal build-service hostname'; Pattern = '(?i)\b(?:[A-Za-z0-9-]+\.)*internal\.api\.openai\.org\b' },
        @{ Name = 'GitHub token'; Pattern = '(?i)\bgh[pousr]_[A-Za-z0-9]{20,}\b' },
        @{ Name = 'OpenAI-style secret key'; Pattern = '\bsk-[A-Za-z0-9_-]{20,}\b' },
        @{ Name = 'Google API key'; Pattern = '\bAIza[0-9A-Za-z_-]{30,}\b' },
        @{ Name = 'AWS access key'; Pattern = '\bAKIA[0-9A-Z]{16}\b' },
        @{ Name = 'private key material'; Pattern = '-----BEGIN [A-Z ]*PRIVATE KEY-----' },
        @{ Name = 'probable plaintext credential assignment'; Pattern = '(?im)\b(api[_-]?key|auth[_-]?key|access[_-]?token|secret|password)\b\s*(?::\s*["'']?[A-Za-z0-9_./+=-]{16,}|=\s*["''][A-Za-z0-9_./+=-]{16,})' }
    )

    $scannerPath = 'scripts/check-public-repo.ps1'
    foreach ($path in $tracked) {
        $normalized = $path -replace '\\', '/'
        if ($normalized -eq $scannerPath) { continue }

        $absolute = Join-Path $root $path
        if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { continue }
        $bytes = [System.IO.File]::ReadAllBytes($absolute)
        if ($bytes.Length -gt 5MB) { continue }
        if ($bytes -contains 0) { continue }

        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        foreach ($rule in $contentPatterns) {
            $matches = [regex]::Matches($text, $rule.Pattern)
            foreach ($match in $matches) {
                if ($rule.Name -eq 'probable plaintext credential assignment' -and
                    $match.Value -match '(?i)(test|example|dummy|placeholder|redacted)') {
                    continue
                }
                $failures.Add("$($rule.Name) found in tracked text file: $normalized")
            }
        }
    }

    if ($failures.Count -gt 0) {
        $failures | Sort-Object -Unique | ForEach-Object { Write-Error $_ }
        throw "Public repository hygiene check failed with $($failures.Count) finding(s)."
    }

    Write-Host "Public repository hygiene check passed for $($tracked.Count) tracked files." -ForegroundColor Green
}
finally {
    Pop-Location
}
