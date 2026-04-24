Set-StrictMode -Version Latest

$script:CertSubject  = 'CN=KeePassPasskeyProvider'
$script:SignToolPath = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

function Write-Step([string]$msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Assert-Elevation {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]$id
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script must run as Administrator."
        Write-Warning "Re-launch PowerShell as Admin and run the script again."
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

# Returns hashtable: FileVersion, Version (e.g. "0.1.0-beta.1")
function Get-BuildVersions([string]$RepoRoot) {
    $props = [xml](Get-Content "$RepoRoot\Directory.Build.props")
    $pg = $props.Project.PropertyGroup
    $fileVersion = $pg.FileVersion
    if (-not $fileVersion) { throw "FileVersion not found in Directory.Build.props" }
    $prefix  = $pg.VersionPrefix
    $suffix  = $pg.VersionSuffix
    $version = if ($suffix) { "$prefix-$suffix" } else { $prefix }
    return @{ FileVersion = $fileVersion; Version = $version }
}

# Builds the MSIX wapproj, patching the manifest version beforehand and restoring it after.
function Invoke-BuildWapproj {
    param(
        [string]$RepoRoot,
        [string]$Configuration,
        [string]$MSBuild
    )
    $versions = Get-BuildVersions $RepoRoot
    $manifest         = "$RepoRoot\src\KeePassPasskeyProvider.Package\Package.appxmanifest"
    $originalContent  = [IO.File]::ReadAllText($manifest)
    $patchedContent   = $originalContent -replace '\bVersion="(\d+\.){3}\d+"', "Version=`"$($versions.FileVersion)`""
    [IO.File]::WriteAllText($manifest, $patchedContent)

    # Restore with PublishReadyToRun=true so the runtime pack is in the NuGet cache before msbuild publish.
    $csproj = "$RepoRoot\src\KeePassPasskeyProvider\KeePassPasskeyProvider.csproj"
    & dotnet restore $csproj -r win-x64 /p:PublishReadyToRun=true --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed with exit code $LASTEXITCODE" }

    $wapproj = "$RepoRoot\src\KeePassPasskeyProvider.Package\KeePassPasskeyProvider.Package.wapproj"
    try {
        & $MSBuild $wapproj `
            /p:Configuration=$Configuration `
            /p:Platform=x64 `
            /p:PlatformToolset=v145 `
            /p:SolutionDir="$RepoRoot\" `
            /p:AppxPackageDir="$RepoRoot\build\AppPackages\" `
            /p:AppxBundle=Never `
            /p:UapAppxPackageBuildMode=SideLoadOnly `
            /p:AppxPackageSigningEnabled=false `
            /m /v:minimal
        if ($LASTEXITCODE -ne 0) { throw "msbuild failed with exit code $LASTEXITCODE" }
        Write-Host "  Build OK."
    } finally {
        [IO.File]::WriteAllText($manifest, $originalContent)
    }
}

# Builds the KeePassPasskey plugin DLL.
function Invoke-BuildPlugin {
    param(
        [string]$RepoRoot,
        [string]$Configuration,
        [string]$MSBuild
    )
    $csproj = "$RepoRoot\src\KeePassPasskeyPlugin\KeePassPasskeyPlugin.csproj"
    & $MSBuild $csproj `
        /p:Configuration=$Configuration `
        /p:SolutionDir="$RepoRoot\" `
        /m /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "msbuild failed with exit code $LASTEXITCODE" }
    Write-Host "  Build OK."
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

# Finds (or creates) the self-signed cert in CurrentUser\My.
function Get-OrCreateCertificate([switch]$SkipCreate) {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $script:CertSubject } |
            Sort-Object NotBefore -Descending |
            Select-Object -First 1

    if ($cert) {
        Write-Host "  Found existing cert  Thumbprint=$($cert.Thumbprint)  Expires=$($cert.NotAfter)"
        return $cert
    }

    if ($SkipCreate) { throw "No cert found in CurrentUser\My with subject '$script:CertSubject' - remove -SkipCert to create one." }

    Write-Step "Creating self-signed certificate"
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $script:CertSubject `
        -KeyUsage DigitalSignature `
        -FriendlyName 'KeePassPasskey Test' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    Write-Host "  Created  Thumbprint=$($cert.Thumbprint)"
    return $cert
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

# Signs an MSIX with the given certificate thumbprint.
function Invoke-SignMsix([string]$MsixPath, [string]$Thumbprint) {
    if (-not (Test-Path $script:SignToolPath)) {
        throw "signtool.exe not found at:`n  $script:SignToolPath`nInstall the Windows SDK 10.0.26100."
    }
    & $script:SignToolPath sign /fd SHA256 /sha1 $Thumbprint $MsixPath
    if ($LASTEXITCODE -ne 0) { throw "signtool exited with code $LASTEXITCODE" }
    Write-Host "  Signed OK."
}

Export-ModuleMember -Function Write-Step, Assert-Elevation, Find-MSBuild, Get-BuildVersions,
                               Invoke-BuildWapproj, Invoke-BuildPlugin, Find-MsixPath,
                               Get-OrCreateCertificate, Add-TrustedCertificate, Invoke-SignMsix
