@echo off
setlocal
cd /d "%~dp0"
echo MailScope build is starting...
echo Detailed output is also saved to build-log.txt.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& '.\scripts\install.ps1' *>&1 | Tee-Object -FilePath '.\build-log.txt'"
set ERR=%ERRORLEVEL%
echo.
if not "%ERR%"=="0" (
  echo Build failed. Open build-log.txt for details.
) else (
  echo Build finished successfully.
)
pause
exit /b %ERR%
