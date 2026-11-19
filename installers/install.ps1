# Installateur Windows 10 / 11 pour ssha
# Installe ssha.exe dans %LOCALAPPDATA%\Programs\ssha et l'ajoute au PATH utilisateur.

[CmdletBinding()]
param(
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"

$Repo = "gigi74168/SSHA"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\ssha"
$DestExe = Join-Path $InstallDir "ssha.exe"

Write-Host "[ssha] Installation de ssha pour Windows..." -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Detect local repository root if run from a cloned checkout
$RepoRoot = $null
if ($PSScriptRoot) {
    $Candidate = Split-Path -Parent $PSScriptRoot
    if (Test-Path (Join-Path $Candidate "Cargo.toml")) {
        $RepoRoot = $Candidate
    }
}
if (-not $RepoRoot -and (Test-Path ".\Cargo.toml")) {
    $RepoRoot = (Get-Location).Path
}

$Installed = $false

# 1. Reuse already-built local release binary if present
if ($RepoRoot -and -not $Rebuild) {
    $LocalExe = Join-Path $RepoRoot "target\release\ssha.exe"
    if (Test-Path $LocalExe) {
        Write-Host "[ssha] Copie du binaire local : $LocalExe" -ForegroundColor Cyan
        Copy-Item -Path $LocalExe -Destination $DestExe -Force
        $Installed = $true
    }
}

# 2. Build locally if inside repo and Cargo is available
if (-not $Installed -and $RepoRoot -and (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "[ssha] Compilation de ssha en mode release (cela peut prendre 1-2 minutes)..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "La compilation Cargo a échoué (code $LASTEXITCODE)."
        }
        Copy-Item -Path (Join-Path $RepoRoot "target\release\ssha.exe") -Destination $DestExe -Force
        $Installed = $true
    } finally {
        Pop-Location
    }
}

# 3. Otherwise download prebuilt binary from GitHub Releases
if (-not $Installed) {
    $DownloadUrl = "https://github.com/$Repo/releases/latest/download/ssha-windows-x86_64.exe"
    Write-Host "[ssha] Téléchargement de la dernière release Windows..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestExe -UseBasicParsing
        $Installed = $true
    } catch {
        Write-Host "[✗] Impossible de télécharger depuis $DownloadUrl." -ForegroundColor Red
        Write-Host "    Si aucune release n'est encore publiée, installe Rust (https://rustup.rs)," -ForegroundColor Yellow
        Write-Host "    clone le dépôt et relance .\installers\install.ps1" -ForegroundColor Yellow
        return
    }
}

# Add InstallDir to User PATH permanently (no admin required)
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
$PathParts = $UserPath -split ';' | Where-Object { $_.Trim() -ne "" }

$AlreadyInPath = $false
foreach ($part in $PathParts) {
    if ($part.TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) {
        $AlreadyInPath = $true
        break
    }
}

if (-not $AlreadyInPath) {
    $NewUserPath = if ($UserPath.Trim() -eq "") { $InstallDir } else { "$UserPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    Write-Host "[✓] Dossier ajouté au PATH utilisateur Windows : $InstallDir" -ForegroundColor Green

    # Broadcast WM_SETTINGCHANGE so new terminals see the updated PATH immediately
    try {
        $Signature = @"
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
"@
        $Win32 = Add-Type -MemberDefinition $Signature -Name "Win32Broadcast" -Namespace "SshaInstaller" -PassThru
        $Result = [UIntPtr]::Zero
        [void]$Win32::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$Result)
    } catch {
        # Non-fatal if broadcast fails
    }
}

# Also add to current PowerShell session immediately
if ($env:Path -notlike "*$InstallDir*") {
    $env:Path = "$InstallDir;$env:Path"
}

Write-Host ""
Write-Host "[✓] ssha est installé dans : $DestExe" -ForegroundColor Green
Write-Host "[✓] Ouvre PowerShell, CMD ou Windows Terminal et tape simplement : ssha" -ForegroundColor Green
