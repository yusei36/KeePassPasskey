#Requires -Version 5.1
<#
.SYNOPSIS
    Signs and installs the KeePassPasskey MSIX package.

.DESCRIPTION
    1. Builds the MSIX via msbuild (wapproj).
    2. Creates a self-signed cert (CN=KeePassPasskeyProvider) if one doesn't exist.
    3. Signs the MSIX with that cert.
    4. Trusts the cert in LocalMachine\TrustedPeople (requires elevation).
    5. Installs the MSIX package.

.PARAMETER Configuration
    Build configuration: Debug or Release. Defaults to Debug.

.PARAMETER SkipBuild
    Skip the msbuild step; use if you already have a built MSIX.

.PARAMETER SkipCert
    Skip cert creation; use if the cert already exists in CurrentUser\My.

.EXAMPLE
    .\sign-and-install.ps1
    .\sign-and-install.ps1 -Configuration Release
    .\sign-and-install.ps1 -SkipBuild -SkipCert
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$SkipBuild,
    [switch]$SkipCert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot       = Split-Path $PSScriptRoot -Parent
$AppPackagesDir = "$RepoRoot\build\AppPackages"

$versions = Get-BuildVersions $RepoRoot
Write-Host "KeePassPasskey $($versions.Version)  [$Configuration]" -ForegroundColor White

Assert-Elevation

# ── 0. Build MSIX ──────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "Building MSIX package (msbuild)"
    $msbuild = Find-MSBuild
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild
}

$MsixPath = Find-MsixPath -AppPackagesDir $AppPackagesDir -Configuration $Configuration

# ── 1. Cert ────────────────────────────────────────────────────────────────────
Write-Step "Checking for signing certificate"
$cert  = Get-OrCreateCertificate -SkipCreate:$SkipCert
$thumb = $cert.Thumbprint

# ── 2. Trust ───────────────────────────────────────────────────────────────────
Write-Step "Trusting certificate in LocalMachine\TrustedPeople"
Add-TrustedCertificate -Cert $cert

# ── 3. Sign ────────────────────────────────────────────────────────────────────
Write-Step "Signing MSIX"
Invoke-SignMsix -MsixPath $MsixPath -Thumbprint $thumb

# ── 4. Install ─────────────────────────────────────────────────────────────────
Write-Step "Installing MSIX"

$existing = Get-AppxPackage -Name '*KeePassPasskeyProvider*'
if ($existing) {
    Write-Host "  Removing existing package: $($existing.PackageFullName)"
    Remove-AppxPackage -Package $existing.PackageFullName
    Write-Host "  Removed."
}

Add-AppxPackage -Path $MsixPath
Write-Host "  Installed."

Write-Step "Verifying installation"
$pkg = Get-AppxPackage -Name '*KeePassPasskeyProvider*'
if ($pkg) {
    $logDir = "$env:LocalAppData\Packages\$($pkg.PackageFamilyName)\LocalState\Logs"
    Write-Host "  Package installed: $($pkg.PackageFullName)" -ForegroundColor Green
    Write-Host "  InstallLocation  : $($pkg.InstallLocation)"
    Write-Host "  Log directory    : $logDir"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  register via KeePassPasskey Provider UI or register manualy via KeePassPasskeyProvider.exe /register"
    Write-Host "  Enable in: Settings -> Accounts -> Passkeys -> Advanced Options"
    Write-Host "  Copy KeePassPasskey.dll to KeePass Plugins folder"

    Write-Step "Launching KeePassPasskey Provider UI"
    $exe = Join-Path $pkg.InstallLocation 'KeePassPasskeyProvider\KeePassPasskeyProvider.exe'
    if (Test-Path $exe) {
        Start-Process $exe
        Write-Host "  Launched." -ForegroundColor Green
    } else {
        Write-Warning "Executable not found at: $exe"
    }
} else {
    Write-Warning "Package not found after install - check above for errors."
}
