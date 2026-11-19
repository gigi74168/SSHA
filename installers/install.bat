@echo off
chcp 65001 >nul
echo Lancement de l'installateur ssh-a pour Windows...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
echo.
pause
