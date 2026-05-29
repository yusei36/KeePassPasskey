# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
Set-StrictMode -Version Latest

$script:CertSubject    = 'CN=KeePassPasskey'
$script:DevCertSubject = 'CN=KeePassPasskey Dev'
# Debug builds use a dev publisher + dev CLSID so they coexist with a Release install.
# These must match the #if DEBUG values in PluginConstants.cs.
$script:ReleaseClsid = '4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e'
$script:DevClsid     = 'f048763a-d151-4fb0-b96e-315c543b2431'
$script:SignToolPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

# Signing cert subject for a build configuration. Debug = dev identity, Release = product identity.
function Get-CertSubject([string]$Configuration) {
    if ($Configuration -eq 'Debug') { return $script:DevCertSubject }
    return $script:CertSubject
}

function Write-Step([string]$msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Assert-Elevation {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]$id
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script must run as Administrator."
        Write-Warning "Re-launch PowerShell as Admin and run the script again."
        # Keep the window open so the message is readable when launched from a profile that closes
        # its console on exit. Skip the wait when there is no interactive console (e.g. CI).
        if ([Environment]::UserInteractive) {
            Read-Host "Press Enter to close" | Out-Null
        }
        exit 1
    }
}

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found - is Visual Studio installed?" }
    $msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' |
               Select-Object -First 1
    if (-not $msbuild) { throw "MSBuild.exe not found via vswhere." }
    return $msbuild
}

# Returns hashtable: FileVersion, Version (e.g. "1.0.0-dev")
# Mirrors the MSBuild rule in Directory.Build.props: Debug builds get 'dev' unless VersionSuffix is explicitly set.
function Get-BuildVersions([string]$RepoRoot, [string]$Configuration = '') {
    $props = [xml](Get-Content "$RepoRoot\src\Directory.Build.props")
    $fileVersionNode = $props.SelectSingleNode('//FileVersion')
    if (-not $fileVersionNode) { throw "FileVersion not found in src/Directory.Build.props" }
    $fileVersion = $fileVersionNode.InnerText
    $prefixNode  = $props.SelectSingleNode('//VersionPrefix')
    $suffixNode  = $props.SelectSingleNode('//VersionSuffix')
    $prefix = if ($prefixNode) { $prefixNode.InnerText } else { '' }
    $suffix = if ($suffixNode) { $suffixNode.InnerText } else { '' }
    # Debug is always 'dev'
    if ($Configuration -eq 'Debug') { $suffix = 'dev' }
    $version = if ($suffix) { "$prefix-$suffix" } else { $prefix }
    return @{ FileVersion = $fileVersion; Version = $version }
}

# Publishes the provider exe via dotnet publish (handles restore; single-file bundling when -Optimized).
function Invoke-PublishProvider {
    param(
        [string]$RepoRoot,
        [string]$Configuration,
        [switch]$Optimized
    )
    $csproj = "$RepoRoot\src\KeePassPasskeyProvider\KeePassPasskeyProvider.csproj"
    $outDir = "$RepoRoot\build\$Configuration\KeePassPasskeyProvider"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($Optimized) {
        & dotnet publish $csproj -c $Configuration -r win-x64 -o $outDir --nologo /p:Optimized=true
    } else {
        & dotnet publish $csproj -c $Configuration -r win-x64 -o $outDir --nologo
    }
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }
    Write-Host "  Build OK.  ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
}

# Builds the MSIX wapproj, patching the manifest version beforehand and restoring it after.
function Invoke-BuildWapproj {
    param(
        [string]$RepoRoot,
        [string]$Configuration,
        [string]$MSBuild,
        [switch]$Optimized
    )
    $versions = Get-BuildVersions $RepoRoot
    $manifest         = "$RepoRoot\src\KeePassPasskeyProvider.Package\Package.appxmanifest"
    $originalContent  = [IO.File]::ReadAllText($manifest)
    $patchedContent   = $originalContent -replace '\bVersion="(\d+\.){3}\d+"', "Version=`"$($versions.FileVersion)`""
    # Debug builds get the dev publisher + dev CLSID so they install and register beside a Release
    # build, plus a "Dev" display name so they are distinguishable in the Start menu / Settings.
    if ($Configuration -eq 'Debug') {
        $patchedContent = $patchedContent -replace 'Publisher="CN=KeePassPasskey"', "Publisher=`"$script:DevCertSubject`""
        $patchedContent = $patchedContent -replace [regex]::Escape($script:ReleaseClsid), $script:DevClsid
        $patchedContent = $patchedContent -replace '<DisplayName>KeePassPasskey</DisplayName>', '<DisplayName>KeePassPasskey Dev</DisplayName>'
        $patchedContent = $patchedContent -replace 'DisplayName="KeePassPasskey"', 'DisplayName="KeePassPasskey Dev"'
        $patchedContent = $patchedContent -replace 'DisplayName="KeePassPasskey \(provider\)"', 'DisplayName="KeePassPasskey Dev (provider)"'
        $patchedContent = $patchedContent -replace 'DisplayName="KeePassPasskey \(tray\)"', 'DisplayName="KeePassPasskey Dev (tray)"'
    }
    [IO.File]::WriteAllText($manifest, $patchedContent)

    $wapproj = "$RepoRoot\src\KeePassPasskeyProvider.Package\KeePassPasskeyProvider.Package.wapproj"
    # Build the arg list as an array. Only add /p:Optimized when set, so that when it is omitted the
    # props default (Release => Optimized=true) still applies.
    $wapArgs = @(
        $wapproj,
        "/p:Configuration=$Configuration",
        '/p:Platform=x64',
        '/p:PlatformToolset=v145',
        "/p:SolutionDir=$RepoRoot\",
        "/p:AppxPackageDir=$RepoRoot\build\AppPackages\",
        '/p:AppxBundle=Never',
        '/p:UapAppxPackageBuildMode=SideLoadOnly',
        '/p:AppxPackageSigningEnabled=false'
    )
    if ($Optimized) { $wapArgs += '/p:Optimized=true' }
    $wapArgs += @('/m', '/v:minimal')
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $MSBuild $wapArgs
        if ($LASTEXITCODE -ne 0) { throw "msbuild failed with exit code $LASTEXITCODE" }
        Write-Host "  Build OK.  ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
    } finally {
        [IO.File]::WriteAllText($manifest, $originalContent)
    }
}

# Builds the KeePassPasskey plugin DLL. -Optimized turns on IL optimization for a Debug-identity build.
function Invoke-BuildPlugin {
    param(
        [string]$RepoRoot,
        [string]$Configuration,
        [switch]$Optimized
    )
    $csproj = "$RepoRoot\src\KeePassPasskeyPlugin\KeePassPasskeyPlugin.csproj"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($Optimized) {
        & dotnet build $csproj -c $Configuration /p:SolutionDir="$RepoRoot\" --nologo /p:Optimized=true
    } else {
        & dotnet build $csproj -c $Configuration /p:SolutionDir="$RepoRoot\" --nologo
    }
    if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
    Write-Host "  Build OK.  ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)"
}

# Returns the path to the .msix file for the given configuration.
function Find-MsixPath([string]$AppPackagesDir, [string]$Configuration) {
    $configSuffix = if ($Configuration -eq 'Debug') { '_Debug' } else { '' }
    $folder = Get-ChildItem $AppPackagesDir -Directory -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like "*KeePassPasskeyProvider*x64${configSuffix}_Test" } |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1
    if (-not $folder) { throw "No MSIX output folder found under $AppPackagesDir" }
    $msix = Get-ChildItem $folder.FullName -Filter '*.msix' | Select-Object -First 1 -ExpandProperty FullName
    if (-not $msix) { throw "No .msix file found in $($folder.FullName)" }
    return $msix
}

# Finds (or creates) the self-signed cert in CurrentUser\My for the given subject.
function Get-OrCreateCertificate([string]$Subject = $script:CertSubject, [switch]$SkipCreate) {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $Subject } |
            Sort-Object NotBefore -Descending |
            Select-Object -First 1

    if ($cert) {
        Write-Host "  Found existing cert  Subject=$Subject  Thumbprint=$($cert.Thumbprint)  Expires=$($cert.NotAfter)"
        return $cert
    }

    if ($SkipCreate) { throw "No cert found in CurrentUser\My with subject '$Subject' - remove -SkipCert to create one." }

    Write-Step "Creating self-signed certificate ($Subject)"
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $Subject `
        -KeyUsage DigitalSignature `
        -FriendlyName ($Subject -replace '^CN=', '') `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(5) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    Write-Host "  Created  Thumbprint=$($cert.Thumbprint)"
    return $cert
}

# Returns true if the certificate is already in LocalMachine\TrustedPeople (read-only, no elevation needed).
function Test-CertificateTrusted([string]$Thumbprint) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'LocalMachine')
    $store.Open('ReadOnly')
    $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
    $store.Close()
    return [bool]$found
}

# Trusts the certificate in LocalMachine\TrustedPeople (requires elevation).
function Add-TrustedCertificate([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'LocalMachine')
    $store.Open('ReadWrite')
    $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
    if ($existing) {
        Write-Host "  Already trusted."
    } else {
        $store.Add($Cert)
        Write-Host "  Cert trusted."
    }
    $store.Close()
}

# Signs any file with the given certificate thumbprint.
function Invoke-SignFile([string]$FilePath, [string]$Thumbprint) {
    if (-not (Test-Path $script:SignToolPath)) {
        throw "signtool.exe not found at:`n  $script:SignToolPath`nInstall the Windows SDK 10.0.26100."
    }
    & $script:SignToolPath sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 $Thumbprint /q $FilePath
    if ($LASTEXITCODE -ne 0) { throw "signtool exited with code $LASTEXITCODE" }
    Write-Host "  Signed OK: $(Split-Path $FilePath -Leaf)"
}

function Invoke-SignMsix([string]$MsixPath, [string]$Thumbprint) {
    Invoke-SignFile -FilePath $MsixPath -Thumbprint $Thumbprint
}

function Invoke-GenerateLicenseNotices {
    param(
        [string]$RepoRoot,
        [string]$OutputFile
    )
    $toolList = & dotnet tool list --global 2>&1
    if (-not ($toolList | Select-String 'nuget-license')) {
        Write-Host "  Installing nuget-license..."
        & dotnet tool install --global nuget-license --verbosity quiet
        if ($LASTEXITCODE -ne 0) { throw "Failed to install nuget-license" }
    }

    $projects = Get-ChildItem -Path "$RepoRoot\src" -Filter '*.csproj' -Recurse |
                       Select-Object -ExpandProperty FullName

    Write-Host "  Restoring NuGet packages..."
    foreach ($proj in $projects) {
        & dotnet restore $proj --verbosity quiet
        if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed for $proj (exit $LASTEXITCODE)" }
    }

    $result   = [System.Collections.Generic.List[string]]::new()
    $seenPkgs = @{}

    foreach ($proj in $projects) {
        $projName  = [IO.Path]::GetFileNameWithoutExtension($proj)
        $lines     = & nuget-license -i $proj --include-transitive
        if ($LASTEXITCODE -ne 0) { throw "nuget-license failed (exit $LASTEXITCODE) for $(Split-Path $proj -Leaf)" }
        $dataLines = @($lines | Where-Object { $_ })

        $result.Add('')
        $result.Add("# $projName")
        if ($dataLines.Count -eq 0) {
            $result.Add('  (no third-party packages)')
        } else {
            foreach ($line in $dataLines) { $result.Add([string]$line) }
        }

        $jsonLines = & nuget-license -i $proj --include-transitive -o Json
        if ($LASTEXITCODE -ne 0) { throw "nuget-license JSON pass failed for $(Split-Path $proj -Leaf)" }
        ($jsonLines | ConvertFrom-Json) | ForEach-Object {
            $key = "$($_.PackageId)_$($_.PackageVersion)"
            if (-not $seenPkgs.ContainsKey($key)) { $seenPkgs[$key] = $_ }
        }
    }

    # SPDX-identified packages grouped by expression, text fetched from the SPDX data repository
    $byLicense = $seenPkgs.Values |
                 Where-Object { $_.License } |
                 Group-Object License |
                 Sort-Object Name

    $result.Add('')
    $result.Add('---')
    $result.Add('# License Texts')

    foreach ($group in $byLicense) {
        $expression = $group.Name
        $pkgs       = $group.Group | Sort-Object PackageId

        $result.Add('')
        $result.Add("## $expression")
        $result.Add('')
        $result.Add('Packages:')
        foreach ($pkg in $pkgs) { $result.Add("  $($pkg.PackageId) $($pkg.PackageVersion)") }
        $result.Add('')

        $spdxUrl = "https://raw.githubusercontent.com/spdx/license-list-data/main/text/$expression.txt"
        try {
            $licText = (Invoke-WebRequest -Uri $spdxUrl -UseBasicParsing -ErrorAction Stop).Content
            foreach ($line in ($licText -split '\r?\n')) { $result.Add($line) }
        } catch {
            $result.Add("[License text unavailable. See: $spdxUrl]")
        }
    }

    $result | Set-Content -Path $OutputFile -Encoding utf8
    Write-Host "  Generated: $(Split-Path $OutputFile -Leaf)"
}

# Reads ProductVersion (includes git hash) from the plugin DLL via PE resource - no assembly loading.
function Get-PluginVersion([string]$BuildDir) {
    $dllPath = Join-Path $BuildDir 'KeePassPasskey.dll'
    if (-not (Test-Path $dllPath)) { throw "Plugin DLL not found: $dllPath" }
    return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dllPath).ProductVersion
}

function Invoke-ILRepack {
    param(
        [string]$BuildDir,
        [string]$Configuration
    )

    $toolList = & dotnet tool list --global 2>&1
    if (-not ($toolList | Select-String 'dotnet-ilrepack')) {
        Write-Host "  Installing dotnet-ilrepack..."
        & dotnet tool install --global dotnet-ilrepack --verbosity quiet
        if ($LASTEXITCODE -ne 0) { throw "Failed to install dotnet-ilrepack" }
    }

    $primaryDll = Join-Path $BuildDir 'KeePassPasskey.dll'
    if (-not (Test-Path $primaryDll)) { throw "Primary DLL not found: $primaryDll" }

    # Sort: third-party packages first, then KeePassPasskey* - ensures Newtonsoft.Json
    # is already loaded by the time ILRepack processes KeePassPasskeyShared.dll.
    $secondaryDlls = @(Get-ChildItem $BuildDir -Filter '*.dll' |
                       Where-Object { $_.Name -ne 'KeePassPasskey.dll' } |
                       Sort-Object { if ($_.Name -like 'KeePassPasskey*') { 1 } else { 0 } }, Name |
                       Select-Object -ExpandProperty FullName)

    if ($secondaryDlls.Count -eq 0) {
        Write-Host "  No secondary DLLs found; skipping merge."
        return
    }

    $mergedDll  = Join-Path $BuildDir 'KeePassPasskey_merged.dll'
    $repackArgs = @("/out:$mergedDll") + $primaryDll + $secondaryDlls

    & ilrepack @repackArgs
    if ($LASTEXITCODE -ne 0) { throw "ILRepack failed with exit code $LASTEXITCODE" }

    Move-Item $mergedDll $primaryDll -Force

    $mergedPdb = [IO.Path]::ChangeExtension($mergedDll, '.pdb')
    if (Test-Path $mergedPdb) {
        Move-Item $mergedPdb ([IO.Path]::ChangeExtension($primaryDll, '.pdb')) -Force
    }

    foreach ($dll in $secondaryDlls) {
        Remove-Item $dll -Force
        $pdb = [IO.Path]::ChangeExtension($dll, '.pdb')
        if (Test-Path $pdb) { Remove-Item $pdb -Force }
    }

    Write-Host "  Merged $($secondaryDlls.Count + 1) assemblies into KeePassPasskey.dll"
}

Export-ModuleMember -Function Write-Step, Assert-Elevation, Find-MSBuild, Get-BuildVersions, Get-CertSubject,
                               Invoke-PublishProvider, Invoke-BuildWapproj, Invoke-BuildPlugin, Find-MsixPath,
                               Get-OrCreateCertificate, Test-CertificateTrusted, Add-TrustedCertificate,
                               Invoke-SignFile, Invoke-SignMsix,
                               Invoke-GenerateLicenseNotices, Get-PluginVersion, Invoke-ILRepack
