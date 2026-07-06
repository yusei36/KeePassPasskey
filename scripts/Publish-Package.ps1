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

.PARAMETER Store
    Build the Microsoft Store channel: stamps the Partner Center package identity + Store CLSID, builds
    unsigned (the Store re-signs), and emits the bare .msix for Partner Center upload instead of the zip.
    Release only.

.EXAMPLE
    .\Publish-Package.ps1
    .\Publish-Package.ps1 -Dev
    .\Publish-Package.ps1 -Store
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
    [switch]$NoOptimize,
    [switch]$Store
)

# -Dev maps to the Debug identity. Output is release-like optimized by default (see -NoOptimize);
# Configuration here only chooses product (Release) vs dev (Debug) identity. Debug auto-stamps 'dev'.
if ($Dev) { $Configuration = 'Debug' }

# Store is a Release-only channel and is uploaded unsigned (the Store re-signs).
if ($Store) {
    if ($Configuration -ne 'Release') { throw "-Store is only valid with the Release configuration (not -Dev / -Configuration Debug)." }
    $SkipSign = $true
}

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
    Invoke-PublishProvider -RepoRoot $RepoRoot -Configuration $Configuration -Optimized:$optimized -Store:$Store

    # Plugin is built and merged BEFORE the MSIX so the wapproj can bundle the single merged DLL
    # under KeePassPasskeyPlugin\ (the provider copies it into KeePass's Plugins folder).
    Write-Step "Building KeePassPasskey plugin DLL"
    Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration -Optimized:$optimized

    Write-Step "Merging plugin DLLs with ILRepack"
    Invoke-ILRepack -BuildDir "$RepoRoot\build\$Configuration" -Configuration $Configuration

    Write-Step "Building MSIX package"
    Invoke-BuildWapproj -RepoRoot $RepoRoot -Configuration $Configuration -MSBuild $msbuild -Optimized:$optimized -Store:$Store
}

# -- 3. Locate build artifacts --------------------------------------------------
$MsixPath = Find-MsixPath -AppPackagesDir $AppPackagesDir -Configuration $Configuration
$buildDir = "$RepoRoot\build\$Configuration"

# Store channel: emit the unsigned MSIX for Partner Center upload; no signing, no zip.
if ($Store) {
    $storeMsix = "$RepoRoot\build\KeePassPasskeyProvider.Package_$($versions.FileVersion)_x64_Store.msix"
    Copy-Item $MsixPath $storeMsix -Force
    Write-Step "Done (Store channel)"
    Write-Host "  Unsigned MSIX for Partner Center upload (includes bundled plugin):" -ForegroundColor Green
    Write-Host "    $storeMsix" -ForegroundColor Green
    return
}

# -- 4. Sign MSIX ---------------------------------------------------------------
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

# -- 5. Assemble zip ------------------------------------------------------------
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

# -- 6. Antivirus self-check (Microsoft Defender) -------------------------------
# Scan every shipped artifact with the same engine that produces Defender's cloud/ML verdicts, so a
# regression is caught before release. Writes a full per-file report plus a short console overview.
Write-Step "Scanning artifacts with Microsoft Defender"
$scanReport  = "$RepoRoot\build\defender-scan-$($versions.Version)$suffix.txt"
$scanSummary = ''
$scanColor   = 'Green'
$scanFailed  = $false
# Prefer the up-to-date versioned platform copy; fall back to the base install.
$mpCmd = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $mpCmd -and (Test-Path "$env:ProgramFiles\Windows Defender\MpCmdRun.exe")) {
    $mpCmd = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
}

if (-not $mpCmd) {
    $scanSummary = 'SKIPPED - MpCmdRun.exe not found, artifacts were NOT scanned'
    $scanColor   = 'Yellow'
    Write-Host "  WARNING: MpCmdRun.exe not found; Microsoft Defender is unavailable." -ForegroundColor Yellow
    Write-Host "  The release artifacts were NOT antivirus-scanned. Verify on a machine with Defender." -ForegroundColor Yellow
    @(
        'Microsoft Defender scan SKIPPED',
        "  Date:    $(Get-Date -Format 'u')",
        "  Version: $($versions.Version)$suffix ($Configuration)",
        '  Reason:  MpCmdRun.exe not found (Microsoft Defender unavailable on this machine).',
        '  Result:  Artifacts were NOT scanned; this build has not been antivirus-verified.'
    ) | Set-Content $scanReport -Encoding UTF8
} else {
    # Artifacts: the zip, the MSIX, the provider exe + all its loose DLLs, and the merged plugin DLL.
    $providerDir = "$buildDir\KeePassPasskeyProvider"
    $scanTargets = @($zipPath, $MsixPath, "$providerDir\KeePassPasskeyProvider.exe")
    $scanTargets += Get-ChildItem $providerDir -Filter '*.dll' -File | Select-Object -ExpandProperty FullName
    $scanTargets += "$buildDir\KeePassPasskey.dll"
    $scanTargets = $scanTargets | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    # -DisableRemediation: report only, never quarantine/delete the build output. 0 = clean, 2 = threat.
    $results = @(foreach ($file in $scanTargets) {
        & $mpCmd -Scan -ScanType 3 -File $file -DisableRemediation | Out-Null
        $code    = $LASTEXITCODE
        $verdict = switch ($code) { 0 { 'CLEAN' } 2 { 'THREAT' } default { "ERROR($code)" } }
        [pscustomobject]@{ Verdict = $verdict; File = $file }
    })
    $threats = @($results | Where-Object { $_.Verdict -eq 'THREAT' })
    $errored = @($results | Where-Object { $_.Verdict -like 'ERROR*' })
    $clean   = @($results | Where-Object { $_.Verdict -eq 'CLEAN' })

    # Full per-file report to its own file. Cloud (MAPS) state is recorded because the !ml/!cl
    # cloud/ML verdicts only reproduce when cloud-delivered protection is on (2 = Advanced).
    $report  = @(
        'Microsoft Defender scan report',
        "  Date:          $(Get-Date -Format 'u')",
        "  Version:       $($versions.Version)$suffix ($Configuration)",
        "  MpCmdRun:      $mpCmd",
        "  Signatures:    $((Get-MpComputerStatus).AntivirusSignatureVersion)",
        "  Cloud (MAPS):  $((Get-MpPreference).MAPSReporting)  (2 = Advanced)",
        "  Result:        $($results.Count) scanned, $($clean.Count) clean, $($threats.Count) threats, $($errored.Count) errors",
        ''
    )
    $report += $results | ForEach-Object { '  [{0,-9}] {1}' -f $_.Verdict, $_.File }
    $report | Set-Content $scanReport -Encoding UTF8

    if ($threats.Count -gt 0) {
        $scanSummary = "$($threats.Count) THREAT(S) detected - see report"
        $scanColor   = 'Red'
        $scanFailed  = $true
        Write-Host "  THREATS DETECTED in $($threats.Count) file(s):" -ForegroundColor Red
        $threats | ForEach-Object { Write-Host "    $($_.File)" -ForegroundColor Red }
    } elseif ($errored.Count -gt 0) {
        $scanSummary = "$($clean.Count)/$($results.Count) clean, $($errored.Count) could not be scanned"
        $scanColor   = 'Yellow'
        Write-Host "  $scanSummary" -ForegroundColor Yellow
    } else {
        $scanSummary = "all $($results.Count) artifacts clean"
        Write-Host "  $scanSummary" -ForegroundColor Green
    }
    Write-Host "  Report: $scanReport"
}

Write-Step "Done"
Write-Host "  Version:   $productVersion ($Configuration)" -ForegroundColor Green
Write-Host "  Archive:   $zipPath ($zipSize MB)" -ForegroundColor Green
Write-Host "  SHA256:    $hash" -ForegroundColor Green
Write-Host "  AV scan:   $scanSummary" -ForegroundColor $scanColor

# Fail the build (non-zero exit) so CI blocks a release when Defender flags an artifact.
if ($scanFailed) {
    Write-Host ''
    Write-Host "Microsoft Defender flagged one or more artifacts; see $scanReport" -ForegroundColor Red
    exit 1
}