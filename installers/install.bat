@echo off
chcp 65001 >nul
echo Starting the ssha installer for Windows...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
echo.
pause
