# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 5.1
<#
.SYNOPSIS
    Builds, signs, and packages KeePassPasskey for distribution.

.DESCRIPTION
    1. Builds the MSIX (COM server + passkey provider).
    2. Builds the KeePassPasskey.dll KeePass plugin.
    3. Creates / finds a self-signed signing certificate.
    4. Signs the MSIX.
    5. Produces a zip archive ready for distribution:
         KeePassPasskey-<version>.zip
           KeePassPasskeyPlugin/        All plugin DLLs (Release) or DLLs + PDBs (Debug)
           KeePassPasskeyProvider.Package_<version>_x64.msix
           KeePassPasskey.cer
           Install.bat
           README.md
           THIRD_PARTY_NOTICES.txt

.PARAMETER Configuration
    Build configuration: Debug or Release. Defaults to Release.

.PARAMETER SkipBuild
    Skip msbuild steps; use if you already have build output.

.PARAMETER SkipCert
    Skip cert creation; use if the cert already exists in CurrentUser\My.

.PARAMETER SkipSign
    Skip signing and cert export. The zip will contain an unsigned MSIX and no .cer or Install.bat.
    Intended for CI/unsigned builds.

.EXAMPLE
    .\Publish-Package.ps1
    .\Publish-Package.ps1 -Configuration Debug
    .\Publish-Package.ps1 -SkipBuild
    .\Publish-Package.ps1 -Configuration Debug -SkipSign
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipBuild,
    [switch]$SkipCert,
    [switch]$SkipSign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot              = Split-Path $PSScriptRoot -Parent
$AppPackagesDir        = "$RepoRoot\build\AppPackages"
$ThirdPartyNoticesName = 'THIRD_PARTY_NOTICES.txt'

$versions = Get-BuildVersions $RepoRoot
Write-Host "KeePassPasskey $($versions.Version) ($Configuration)" -ForegroundColor White

# -- 1. Generate notices (must precede MSIX build so the file is included) ----
$noticesPath = "$RepoRoot\build\$ThirdPartyNoticesName"
New-Item (Split-Path $noticesPath) -ItemType Directory -Force | Out-Null
Write-Step "Generating third-party license notices"
Invoke-GenerateLicenseNotices -RepoRoot $RepoRoot -OutputFile $noticesPath

# -- 2. Build -------------------------------------------------------------------
if (-not $SkipBuild) {
    $msbuild = Find-MSBuild

    Write-Step "Building MSIX package"
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild

    Write-Step "Building KeePassPasskey plugin DLL"
    Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild
}

# -- 3. Locate build artifacts --------------------------------------------------
$MsixPath = Find-MsixPath -AppPackagesDir $AppPackagesDir -Configuration $Configuration
$buildDir = "$RepoRoot\build\$Configuration"

# -- 4. Merge plugin DLLs -------------------------------------------------------
Write-Step "Merging plugin DLLs with ILRepack"
Invoke-ILRepack -BuildDir $buildDir -Configuration $Configuration

# -- 5. Sign MSIX ---------------------------------------------------------------
$cert = $null
if (-not $SkipSign) {
    Write-Step "Checking for signing certificate"
    $cert  = Get-OrCreateCertificate -SkipCreate:$SkipCert
    $thumb = $cert.Thumbprint

    Write-Step "Signing MSIX"
    Invoke-SignMsix -MsixPath $MsixPath -Thumbprint $thumb

    Write-Step "Signing plugin DLLs"
    Get-ChildItem $buildDir -Filter 'KeePassPasskey*.dll' | ForEach-Object {
        Invoke-SignFile -FilePath $_.FullName -Thumbprint $thumb
    }
}

# -- 6. Assemble zip ------------------------------------------------------------
$versions   = Get-BuildVersions $RepoRoot
$tags       = @()
if ($Configuration -eq 'Debug') { $tags += 'debug' }
if ($SkipSign)                  { $tags += 'unsigned' }
$suffix     = if ($tags.Count -gt 0) { '-' + ($tags -join '-') } else { '' }
$zipName    = "KeePassPasskey-$($versions.Version)$suffix.zip"
$stagingDir = "$RepoRoot\build\publish-staging"
$zipPath    = "$RepoRoot\build\$zipName"

if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item $stagingDir -ItemType Directory | Out-Null

Write-Step "Assembling release archive: $zipName"

$pluginDir  = "$stagingDir\KeePassPasskeyPlugin"
New-Item $pluginDir -ItemType Directory | Out-Null

$extensions = if ($Configuration -eq 'Debug') { '.dll', '.pdb' } else { '.dll' }
Get-ChildItem $buildDir -File | Where-Object { $_.Extension -in $extensions } | Copy-Item -Destination $pluginDir

Copy-Item $MsixPath "$stagingDir\"

if (-not $SkipSign) {
    Export-Certificate -Cert $cert -FilePath "$stagingDir\KeePassPasskey.cer" | Out-Null
    Copy-Item "$PSScriptRoot\Install.bat" "$stagingDir\Install.bat"
}

Copy-Item "$RepoRoot\README.md" "$stagingDir\README.md"
Copy-Item "$RepoRoot\LICENSE"   "$stagingDir\LICENSE"
Copy-Item $noticesPath          "$stagingDir\$ThirdPartyNoticesName"

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath
Remove-Item $stagingDir -Recurse -Force

Write-Host "Archive: $zipPath"


# Verify by listing zip entries
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
Write-Host "Zip entries:"
$zip.Entries | ForEach-Object { Write-Host "  $($_.FullName)  ($([math]::Round($_.Length / 1KB, 1)) KB)" }
$zip.Dispose()

$hash    = (Get-FileHash $zipPath -Algorithm SHA256).Hash
$zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)

$productVersion = Get-PluginVersion -BuildDir $buildDir

Write-Step "Done"
Write-Host "  Version:   $productVersion ($Configuration)" -ForegroundColor Green
Write-Host "  Archive:   $zipPath ($zipSize MB)" -ForegroundColor Green
Write-Host "  SHA256:    $hash" -ForegroundColor Green