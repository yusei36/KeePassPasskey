# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 5.1
<#
.SYNOPSIS
    Builds, signs, and packages KeePassPasskey for distribution.

.DESCRIPTION
    1. Builds the provider app (dotnet publish).
    2. Builds the MSIX package (msbuild wapproj).
    3. Builds the KeePassPasskey.dll KeePass plugin (dotnet build).
    4. Creates / finds a self-signed signing certificate.
    5. Signs the MSIX.
    6. Produces a zip archive ready for distribution:
         KeePassPasskey-<version>.zip
           KeePassPasskeyPlugin/        All plugin DLLs (Release) or DLLs + PDBs (Debug)
           KeePassPasskeyProvider.Package_<version>_x64.msix
           KeePassPasskey.cer
           InstallMsix.bat
           README.md
           THIRD_PARTY_NOTICES.txt

.PARAMETER Configuration
    Selects identity only: Release = product identity, Debug = dev identity (separate cert/publisher
    + CLSID/AAGUID, installs beside a stable release). Output is release-like optimized by default
    (see -NoOptimize). Defaults to Release.

.PARAMETER SkipBuild
    Skip build and publish steps; use if you already have build output.

.PARAMETER SkipCert
    Skip cert creation; use if the cert already exists in CurrentUser\My.

.PARAMETER SkipSign
    Skip signing and cert export. The zip will contain an unsigned MSIX and no .cer or InstallMsix.bat.
    Intended for CI/unsigned builds.

.PARAMETER Dev
    Build the dev-identity package (maps to Configuration Debug): optimized like a release, signed with
    the dev cert, stamped with the 'dev' version suffix, and installable beside a stable release.

.PARAMETER NoOptimize
    Skip release-like optimization (single-file, trimming, IL optimize), producing a plain debuggable
    build. Only meaningful for the Debug configuration; Release stays optimized via the props default.
    The zip is tagged 'unopt'.

.EXAMPLE
    .\Publish-Package.ps1
    .\Publish-Package.ps1 -Dev
    .\Publish-Package.ps1 -Configuration Debug
    .\Publish-Package.ps1 -SkipBuild
    .\Publish-Package.ps1 -Configuration Debug -SkipSign
    .\Publish-Package.ps1 -Configuration Debug -SkipSign -NoOptimize
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipBuild,
    [switch]$SkipCert,
    [switch]$SkipSign,
    [switch]$Dev,
    [switch]$NoOptimize
)

# -Dev maps to the Debug identity. Output is release-like optimized by default (see -NoOptimize);
# Configuration here only chooses product (Release) vs dev (Debug) identity. Debug auto-stamps 'dev'.
if ($Dev) { $Configuration = 'Debug' }

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot              = Split-Path $PSScriptRoot -Parent
$AppPackagesDir        = "$RepoRoot\build\AppPackages"
$ThirdPartyNoticesName = 'THIRD_PARTY_NOTICES.txt'

$versions = Get-BuildVersions $RepoRoot -Configuration $Configuration
Write-Host "KeePassPasskey $($versions.Version) ($Configuration)" -ForegroundColor White

# -- 1. Generate notices (must precede MSIX build so the file is included) ----
$noticesPath = "$RepoRoot\build\$ThirdPartyNoticesName"
New-Item (Split-Path $noticesPath) -ItemType Directory -Force | Out-Null
Write-Step "Generating third-party license notices"
Invoke-GenerateLicenseNotices -RepoRoot $RepoRoot -OutputFile $noticesPath

# -- 2. Build -------------------------------------------------------------------
if (-not $SkipBuild) {
    $msbuild = Find-MSBuild

    # Release-like optimized by default; -NoOptimize produces a plain debuggable build (Debug only).
    $optimized = -not $NoOptimize
    Write-Step "Building provider app"
    Invoke-PublishProvider -RepoRoot $RepoRoot -Configuration $Configuration -Optimized:$optimized

    Write-Step "Building MSIX package"
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild -Optimized:$optimized

    Write-Step "Building KeePassPasskey plugin DLL"
    Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration -Optimized:$optimized
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
    $cert  = Get-OrCreateCertificate -Subject (Get-CertSubject $Configuration) -SkipCreate:$SkipCert
    $thumb = $cert.Thumbprint

    Write-Step "Signing MSIX"
    Invoke-SignMsix -MsixPath $MsixPath -Thumbprint $thumb

    Write-Step "Signing plugin DLLs"
    Get-ChildItem $buildDir -Filter 'KeePassPasskey*.dll' | ForEach-Object {
        Invoke-SignFile -FilePath $_.FullName -Thumbprint $thumb
    }
}

# -- 6. Assemble zip ------------------------------------------------------------
$versions   = Get-BuildVersions $RepoRoot -Configuration $Configuration
$tags       = @()
if ($Configuration -eq 'Debug') { $tags += 'debug' }
if ($NoOptimize)                { $tags += 'unopt' }
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

# Dev-identity (Debug) builds ship plugin PDBs so testers' KeePass logs carry file/line numbers;
# these stay useful after optimization for stack-trace symbolication. Stable Release ships .dll only.
$pluginExtensions = if ($Configuration -eq 'Debug') { '.dll', '.pdb' } else { '.dll' }
Get-ChildItem $buildDir -File | Where-Object { $_.Extension -in $pluginExtensions } | Copy-Item -Destination $pluginDir

Copy-Item $MsixPath "$stagingDir\"

if (-not $SkipSign) {
    Export-Certificate -Cert $cert -FilePath "$stagingDir\KeePassPasskey.cer" | Out-Null
    Copy-Item "$PSScriptRoot\InstallMsix.bat" "$stagingDir\InstallMsix.bat"
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