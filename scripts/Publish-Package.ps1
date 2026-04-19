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
           KeePassPasskey.dll
           KeePassPasskeyProvider.Package_<version>_x64.msix
           Install.ps1

.PARAMETER Configuration
    Build configuration: Debug or Release. Defaults to Release.

.PARAMETER SkipBuild
    Skip msbuild steps; use if you already have build output.

.PARAMETER SkipCert
    Skip cert creation; use if the cert already exists in CurrentUser\My.

.EXAMPLE
    .\publish.ps1
    .\publish.ps1 -Configuration Debug
    .\publish.ps1 -SkipBuild
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipBuild,
    [switch]$SkipCert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot       = Split-Path $PSScriptRoot -Parent
$AppPackagesDir = "$RepoRoot\build\AppPackages"

$versions = Get-BuildVersions $RepoRoot
Write-Host "KeePassPasskey Version:$($versions.Version) File Version: $($versions.FileVersion) [$Configuration]" -ForegroundColor White

# ── 0. Build ───────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    $msbuild = Find-MSBuild

    Write-Step "Building MSIX package (msbuild, Release)"
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild

    Write-Step "Building KeePassPasskey plugin DLL (msbuild, Release)"
    Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild
}

# ── 1. Locate build artifacts ──────────────────────────────────────────────────
$MsixPath = Find-MsixPath -AppPackagesDir $AppPackagesDir -Configuration $Configuration

# ── 2. Sign MSIX ───────────────────────────────────────────────────────────────
Write-Step "Checking for signing certificate"
$cert  = Get-OrCreateCertificate -SkipCreate:$SkipCert
$thumb = $cert.Thumbprint

Write-Step "Signing MSIX"
Invoke-SignMsix -MsixPath $MsixPath -Thumbprint $thumb

# ── 3. Assemble zip ────────────────────────────────────────────────────────────
$versions   = Get-BuildVersions $RepoRoot
$zipName    = "KeePassPasskey-$($versions.Version).zip"
$stagingDir = "$RepoRoot\build\publish-staging"
$zipPath    = "$RepoRoot\build\$zipName"

Write-Step "Assembling release archive: $zipName"

if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item $stagingDir -ItemType Directory | Out-Null

$buildDir   = "$RepoRoot\build\$Configuration"
$pluginDir  = "$stagingDir\KeePassPasskeyPlugin"
New-Item $pluginDir -ItemType Directory | Out-Null

$extensions = if ($Configuration -eq 'Debug') { '.dll', '.pdb' } else { '.dll' }
Get-ChildItem $buildDir -File | Where-Object { $_.Extension -in $extensions } | Copy-Item -Destination $pluginDir
Copy-Item $MsixPath "$stagingDir\"

Export-Certificate -Cert $cert -FilePath "$stagingDir\KeePassPasskeyProvider.cer" | Out-Null
Copy-Item "$PSScriptRoot\Install.bat" "$stagingDir\Install.bat"
Copy-Item "$RepoRoot\README.md"       "$stagingDir\README.md"

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath
Remove-Item $stagingDir -Recurse -Force

Write-Host "  Archive: $zipPath" -ForegroundColor Green
Write-Host "  Contents:"
foreach ($entry in (Get-ChildItem (Split-Path $zipPath))) {
    Write-Host "    $($entry.Name)"
}

# Verify by listing zip entries
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
Write-Host ""
Write-Host "Zip entries:"
$zip.Entries | ForEach-Object { Write-Host "  $($_.FullName)  ($([math]::Round($_.Length / 1KB, 1)) KB)" }
$zip.Dispose()

Write-Step "Done"
Write-Host "  Distribute: $zipPath" -ForegroundColor Green
