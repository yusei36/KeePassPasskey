# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 5.1
<#
.SYNOPSIS
    Builds + installs the dev provider, then launches the development KeePass.

.DESCRIPTION
    Used by the "KeePass (build + install provider)" launch profile. Runs Build-AndInstall.ps1
    (Debug = dev identity) and then starts build\KeePass\KeePass.exe. The debugger is attached to
    this wrapper, not to KeePass; use the plain "KeePass" launch profile to debug the plugin.
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path $PSScriptRoot -Parent

& "$PSScriptRoot\Build-AndInstall.ps1" -Configuration $Configuration

$keepass = Join-Path $RepoRoot 'build\KeePass\KeePass.exe'
if (-not (Test-Path $keepass)) { throw "KeePass not found: $keepass" }
Start-Process $keepass
