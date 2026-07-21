param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,
    [string]$CertificateThumbprint = $env:MAILSCOPE_SIGN_CERT_THUMBPRINT,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    throw 'MAILSCOPE_SIGN_CERT_THUMBPRINT is not configured. A trusted code-signing certificate is required.'
}

$SignTool = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter 'signtool.exe' -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $SignTool) { throw 'Windows SDK signtool.exe was not found.' }

foreach ($Item in $Path) {
    $Resolved = Resolve-Path -LiteralPath $Item -ErrorAction Stop
    & $SignTool.FullName sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Resolved.Path
    if ($LASTEXITCODE -ne 0) { throw "Signing failed: $($Resolved.Path)" }
    & $SignTool.FullName verify /pa /all $Resolved.Path
    if ($LASTEXITCODE -ne 0) { throw "Signature verification failed: $($Resolved.Path)" }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Resolved.Path
    if ($Signature.Status -ne 'Valid') { throw "Authenticode status is not valid for $($Resolved.Path): $($Signature.Status)" }
    Write-Host "Signed and verified: $($Resolved.Path)" -ForegroundColor Green
}
