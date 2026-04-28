#Requires -Version 5.1
<#
.SYNOPSIS
    Signs and installs the KeePassPasskey MSIX package.

.DESCRIPTION
    1. Builds the MSIX via msbuild (wapproj).
    2. Builds the KeePassPasskey plugin DLL.
    3. Creates a self-signed cert (CN=KeePassPasskey) if one doesn't exist.
    4. Signs the MSIX with that cert.
    5. Trusts the cert in LocalMachine\TrustedPeople (requires elevation).
    6. Installs the MSIX package.

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
Write-Host "KeePassPasskey $($versions.Version) ($Configuration)" -ForegroundColor White

Assert-Elevation

# ── 0. Build ───────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    $msbuild = Find-MSBuild
    Write-Step "Building MSIX package (msbuild)"
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild
    Write-Step "Building KeePassPasskey plugin DLL (msbuild)"
    Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild
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
    Stop-Process -Name KeePassPasskeyProvider -Force -ErrorAction SilentlyContinue
    Remove-AppxPackage -Package $existing.PackageFullName
    Write-Host "  Removed."
}

Add-AppxPackage -Path $MsixPath
Write-Host "  Installed."

$pkg = Get-AppxPackage -Name '*KeePassPasskeyProvider*'
if ($pkg) {
    $exe = Join-Path $pkg.InstallLocation 'KeePassPasskeyProvider\KeePassPasskeyProvider.exe'
    if (Test-Path $exe) { Start-Process $exe }

    $logDir         = "$env:LocalAppData\KeePassPasskeyProvider"
    $productVersion = Get-PluginVersion -BuildDir "$RepoRoot\build\$Configuration"

    Write-Step "Done"
    Write-Host "  Version:   $productVersion ($Configuration)" -ForegroundColor Green
    Write-Host "  Package:   $($pkg.PackageFullName)" -ForegroundColor Green
    Write-Host "  Location:  $($pkg.InstallLocation)" -ForegroundColor Green
    Write-Host "  Logs:      $logDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  Auto-registers on first launch (or manually: KeePassPasskeyProvider.exe /register)"
    Write-Host "  Enable in: Settings -> Accounts -> Passkeys -> Advanced Options"
    Write-Host "  Copy DLLs from build\$Configuration\ to KeePass Plugins\KeePassPasskeyPlugin\ folder"
} else {
    Write-Warning "Package not found after install - check above for errors."
}
