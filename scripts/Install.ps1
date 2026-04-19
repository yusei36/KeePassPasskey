#Requires -Version 5.1
<#
.SYNOPSIS
    Installs KeePassPasskey.

.DESCRIPTION
    Trusts the signing certificate embedded in the MSIX and installs the package.
    Run as Administrator.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = [Security.Principal.WindowsPrincipal]$id
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must run as Administrator."
    Read-Host "Press Enter to close"
    exit 1
}

$msix = Get-ChildItem $PSScriptRoot -Filter '*.msix' | Select-Object -First 1 -ExpandProperty FullName
if (-not $msix) { throw "No .msix file found next to this script." }

Write-Step "Trusting signing certificate"
$cer = Get-ChildItem $PSScriptRoot -Filter '*.cer' | Select-Object -First 1 -ExpandProperty FullName
if (-not $cer) { throw "No .cer file found next to this script." }
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
Write-Host "  Cert trusted."

Write-Step "Installing MSIX"
$existing = Get-AppxPackage -Name '*KeePassPasskeyProvider*'
if ($existing) {
    Write-Host "  Removing existing package: $($existing.PackageFullName)"
    Remove-AppxPackage -Package $existing.PackageFullName
}
Add-AppxPackage -Path $msix
Write-Host "  Installed." -ForegroundColor Green

Write-Step "Launching KeePassPasskey Provider UI"
$pkg = Get-AppxPackage -Name '*KeePassPasskeyProvider*'
if ($pkg) {
    $exe = Join-Path $pkg.InstallLocation 'KeePassPasskeyProvider\KeePassPasskeyProvider.exe'
    if (Test-Path $exe) {
        Start-Process $exe
        Write-Host "  Launched." -ForegroundColor Green
    } else {
        Write-Warning "Executable not found at: $exe"
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Copy 'KeePassPasskeyPlugin' folder to your KeePass Plugins folder"
Write-Host "  2. Register via KeePassPasskey Provider UI or: KeePassPasskeyProvider.exe /register"
Write-Host "  3. Enable in: Settings -> Accounts -> Passkeys -> Advanced Options"

Write-Host ""
Read-Host "Press Enter to close"