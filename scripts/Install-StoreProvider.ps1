# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 5.1
<#
.SYNOPSIS
	Builds, signs, and installs the Microsoft Store channel MSIX for LOCAL TESTING.

.DESCRIPTION
	The Store channel package normally ships to Partner Center unsigned (the Store re-signs it).
	To sideload it locally it must be signed with a certificate whose Subject exactly matches the
	Store manifest Publisher (CN=<GUID> from Partner Center). This script creates such a self-signed
	cert, trusts it, signs the Store MSIX, and installs it. It coexists with the GitHub-channel
	package because they have different Package Family Names.

	Steps:
	  1. (unless -SkipBuild) Build the Store MSIX via Publish-Package.ps1 -Store.
	  2. Create / find a self-signed cert whose Subject == the Store Publisher.
	  3. Trust the cert in LocalMachine\TrustedPeople (needs elevation the first time).
	  4. Sign the Store MSIX with that cert.
	  5. Install the package.

	FOR LOCAL TESTING ONLY. The self-signed cert is trusted on this machine only, so the package
	will not install elsewhere. The real Store distribution is signed by Microsoft.

.PARAMETER SkipBuild
	Skip the build; sign + install the existing build\...\_x64_Store.msix.

.PARAMETER SkipCert
	Skip cert creation; the cert must already exist in CurrentUser\My.

.EXAMPLE
	.\Install-StoreProvider.ps1
	.\Install-StoreProvider.ps1 -SkipBuild
#>
param(
	[switch]$SkipBuild,
	[switch]$SkipCert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot = Split-Path $PSScriptRoot -Parent

# -- 0. Build (Store channel) --------------------------------------------------
if (-not $SkipBuild) {
	Write-Step "Building Store MSIX (Publish-Package.ps1 -Store)"
	& "$PSScriptRoot\Publish-Package.ps1" -Store
}

# -- 1. Locate the Store MSIX --------------------------------------------------
$MsixPath = Get-ChildItem "$RepoRoot\build\KeePassPasskeyProvider.Package_*_x64_Store.msix" -ErrorAction SilentlyContinue |
			Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
if (-not $MsixPath) {
	throw "No Store MSIX found in build\. Run without -SkipBuild, or build with Publish-Package.ps1 -Store first."
}
Write-Host "  MSIX: $MsixPath"

# -- 2. Cert (Subject must equal the Store manifest Publisher) -----------------
$storeSubject = Get-StorePublisher
Write-Step "Checking for Store signing certificate ($storeSubject)"
$cert  = Get-OrCreateCertificate -Subject $storeSubject -SkipCreate:$SkipCert
$thumb = $cert.Thumbprint

# -- 3. Trust ------------------------------------------------------------------
Write-Step "Checking certificate trust"
if (Test-CertificateTrusted -Thumbprint $thumb) {
	Write-Host "  Already trusted in LocalMachine\TrustedPeople."
} else {
	Assert-Elevation
	Add-TrustedCertificate -Cert $cert
}

# -- 4. Sign -------------------------------------------------------------------
Write-Step "Signing Store MSIX"
Invoke-SignMsix -MsixPath $MsixPath -Thumbprint $thumb

# -- 5. Install ----------------------------------------------------------------
Write-Step "Installing Store MSIX"
$storeName = Get-StoreIdentityName

# Replace an existing Store install; leaves the GitHub-channel package (different name) untouched.
$existing = Get-AppxPackage -Name $storeName | Select-Object -First 1
if ($existing) {
	Write-Host "  Removing existing package: $($existing.PackageFullName)"
	# Stop only the provider process running from this package, not the GitHub build's.
	Get-Process -Name KeePassPasskeyProvider -ErrorAction SilentlyContinue |
		Where-Object { $_.Path -and $_.Path.StartsWith($existing.InstallLocation, [StringComparison]::OrdinalIgnoreCase) } |
		Stop-Process -Force -ErrorAction SilentlyContinue
	Remove-AppxPackage -Package $existing.PackageFullName
	Write-Host "  Removed."
}

Add-AppxPackage -Path $MsixPath
Write-Host "  Installed."

$pkg = Get-AppxPackage -Name $storeName | Select-Object -First 1
if ($pkg) {
	$exe = "$($pkg.InstallLocation)\KeePassPasskeyProvider\KeePassPasskeyProvider.exe"
	Write-Step "Done"
	Write-Host "  Package:   $($pkg.PackageFullName)" -ForegroundColor Green
	Write-Host "  Publisher: $($pkg.Publisher)" -ForegroundColor Green
	Write-Host "  Location:  $($pkg.InstallLocation)" -ForegroundColor Green
	Write-Host ""
	Write-Host "FOR LOCAL TESTING ONLY - signed with a self-signed cert trusted on this machine." -ForegroundColor Yellow
	Write-Host "Register/check by FULL PATH (the KeePassPasskeyProvider.exe alias is shared with the GitHub build):" -ForegroundColor Yellow
	Write-Host "  & '$exe' /register"
	Write-Host "  & '$exe' /status"
} else {
	Write-Warning "Package not found after install - check above for errors."
}
