$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "MailScope.lnk"
$Launcher = Join-Path $Root "apps\desktop\src-tauri\target\release\mailscope.exe"
$Icon = Join-Path $Root "apps\desktop\src-tauri\icons\icon.ico"

if (-not (Test-Path $Launcher)) {
    throw "Compiled MailScope was not found: $Launcher. Build the application before creating the shortcut."
}

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Launcher
$Shortcut.WorkingDirectory = Split-Path $Launcher
$Shortcut.IconLocation = "$Icon,0"
$Shortcut.Description = "MailScope Privacy-First Email Analysis Platform"
$Shortcut.Save()
Write-Host "Desktop shortcut created: $ShortcutPath" -ForegroundColor Green
