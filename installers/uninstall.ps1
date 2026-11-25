# Windows 10 / 11 uninstaller for ssha
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\ssha"

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "[✓] Removed: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[!] No installation found in $InstallDir" -ForegroundColor Yellow
}

# Clean User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath) {
    $Filtered = ($UserPath -split ';') | Where-Object {
        $_.Trim() -ne "" -and ($_.TrimEnd('\') -ine $InstallDir.TrimEnd('\'))
    }
    [Environment]::SetEnvironmentVariable("Path", ($Filtered -join ';'), "User")
    Write-Host "[✓] User PATH cleaned." -ForegroundColor Green
}

$ConfigDir = Join-Path $env:APPDATA "ssha"
if ($Purge -and (Test-Path $ConfigDir)) {
    Remove-Item -Path $ConfigDir -Recurse -Force
    Write-Host "[✓] Vault removed: $ConfigDir" -ForegroundColor Green
} elseif (Test-Path $ConfigDir) {
    Write-Host "[i] Your encrypted vault was kept in: $ConfigDir" -ForegroundColor Cyan
    Write-Host "    Run again with -Purge to also delete the saved connections."
}
