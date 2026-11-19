# Désinstallateur Windows 10 / 11 pour ssha
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\ssha"

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "[✓] Supprimé : $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[!] Aucune installation trouvée dans $InstallDir" -ForegroundColor Yellow
}

# Clean User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath) {
    $Filtered = ($UserPath -split ';') | Where-Object {
        $_.Trim() -ne "" -and ($_.TrimEnd('\') -ine $InstallDir.TrimEnd('\'))
    }
    [Environment]::SetEnvironmentVariable("Path", ($Filtered -join ';'), "User")
    Write-Host "[✓] PATH utilisateur nettoyé." -ForegroundColor Green
}

$ConfigDir = Join-Path $env:APPDATA "ssha"
if ($Purge -and (Test-Path $ConfigDir)) {
    Remove-Item -Path $ConfigDir -Recurse -Force
    Write-Host "[✓] Coffre-fort supprimé : $ConfigDir" -ForegroundColor Green
} elseif (Test-Path $ConfigDir) {
    Write-Host "[i] Ton coffre-fort chiffré a été conservé dans : $ConfigDir" -ForegroundColor Cyan
    Write-Host "    Relance avec -Purge pour supprimer aussi les connexions enregistrées."
}
