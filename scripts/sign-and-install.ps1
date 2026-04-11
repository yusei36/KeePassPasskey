#Requires -Version 5.1
<#
.SYNOPSIS
    Signs and installs the PasskeyWin11 MSIX package.

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

$RepoRoot  = Split-Path $PSScriptRoot -Parent
$ConfigSuffix = if ($Configuration -eq 'Debug') { '_Debug' } else { '' }
$MsixPath  = "$RepoRoot\src\NativeComServer.Package\AppPackages\NativeComServer.Package_1.0.0.0_x64${ConfigSuffix}_Test\NativeComServer.Package_1.0.0.0_x64${ConfigSuffix}.msix"
$SignTool  = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$CertSubject = 'CN=KeePassPasskeyProvider'

# ── helpers ────────────────────────────────────────────────────────────────────
function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Assert-Elevation {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]$id
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script must run as Administrator (needed to trust the cert and install the MSIX)."
        Write-Warning "Re-launch PowerShell as Admin and run the script again."
        exit 1
    }
}

Assert-Elevation

# ── 0. Build MSIX ──────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "Building MSIX package (msbuild)"

    # Find msbuild via vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found - is Visual Studio installed?" }

    $msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw "MSBuild.exe not found via vswhere." }

    $wapproj = "$RepoRoot\src\NativeComServer.Package\NativeComServer.Package.wapproj"
    & $msbuild $wapproj `
        /p:Configuration=$Configuration `
        /p:Platform=x64 `
        /p:PlatformToolset=v145 `
        /p:SolutionDir="$RepoRoot\" `
        /p:AppxPackageDir="$RepoRoot\src\NativeComServer.Package\AppPackages\" `
        /p:AppxBundle=Never `
        /p:UapAppxPackageBuildMode=SideLoadOnly `
        /p:AppxPackageSigningEnabled=false `
        /m /v:minimal

    if ($LASTEXITCODE -ne 0) { throw "msbuild failed with exit code $LASTEXITCODE" }
    Write-Host "  Build OK."
}

# ── 1. Cert ────────────────────────────────────────────────────────────────────
Write-Step "Checking for signing certificate ($CertSubject)"

$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $CertSubject } |
        Sort-Object NotBefore -Descending |
        Select-Object -First 1

if ($cert -and -not $SkipCert) {
    Write-Host "  Found existing cert  Thumbprint=$($cert.Thumbprint)  Expires=$($cert.NotAfter)"
} else {
    if ($SkipCert) { throw "No cert found in CurrentUser\My with subject '$CertSubject' - remove -SkipCert to create one." }

    Write-Step "Creating self-signed certificate"
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $CertSubject `
        -KeyUsage DigitalSignature `
        -FriendlyName 'PasskeyWin11 Test' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    Write-Host "  Created  Thumbprint=$($cert.Thumbprint)"
}

$thumb = $cert.Thumbprint

# ── 2. Trust ───────────────────────────────────────────────────────────────────
Write-Step "Trusting certificate in LocalMachine\TrustedPeople"

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'LocalMachine')
$store.Open('ReadWrite')
$existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumb }
if ($existing) {
    Write-Host "  Already trusted."
} else {
    $store.Add($cert)
    Write-Host "  Cert trusted."
}
$store.Close()

# ── 3. Sign ────────────────────────────────────────────────────────────────────
Write-Step "Signing MSIX"

if (-not (Test-Path $MsixPath)) {
    throw "MSIX not found at:`n  $MsixPath`nBuild the NativeComServer.Package project first."
}

if (-not (Test-Path $SignTool)) {
    throw "signtool.exe not found at:`n  $SignTool`nInstall the Windows SDK 10.0.26100."
}

& $SignTool sign /fd SHA256 /sha1 $thumb $MsixPath
if ($LASTEXITCODE -ne 0) { throw "signtool exited with code $LASTEXITCODE" }
Write-Host "  Signed OK."

# ── 4. Install ─────────────────────────────────────────────────────────────────
Write-Step "Installing MSIX"

# Remove any existing installation first — Windows blocks re-install of the same
# version when the contents differ (0x80073CFB). Removal is always safe here
# because we're about to re-install immediately.
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
    Write-Host "  Package installed: $($pkg.PackageFullName)" -ForegroundColor Green
    Write-Host "  InstallLocation  : $($pkg.InstallLocation)"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  cd `"$($pkg.InstallLocation)\PasskeyPluginProxy`""
    Write-Host "  .\PasskeyPluginProxy.exe /register"
    Write-Host "  Copy PasskeyWinNative.dll to KeePass Plugins folder"
    Write-Host "  Enable in: Settings → Accounts → Passkeys → Advanced Options"
} else {
    Write-Warning "Package not found after install - check above for errors."
}
