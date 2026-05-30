# SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
# SPDX-License-Identifier: GPL-3.0-or-later
#Requires -Version 5.1
<#
.SYNOPSIS
    Builds + installs the dev provider, starts it, then launches the development KeePass, optionally
    attaching the running Visual Studio for debugging.

.DESCRIPTION
    Used by the "KeePass + ..." launch profiles. Runs Install-Provider.ps1
    (Debug = dev identity), starts the installed provider, then starts build\KeePass\KeePass.exe.

    Any process attached via -DebugProvider / -DebugPlugin keeps its own Visual Studio debug session,
    so this wrapper can return right after attaching without detaching them.

    When run with no arguments (a plain terminal launch, not a VS launch profile), it also builds the
    plugin DLL first, since no IDE build has produced it.

.PARAMETER DebugProvider
    Attach the running Visual Studio to the provider (management/tray) process so its breakpoints hit.

.PARAMETER DebugPlugin
    Attach the running Visual Studio to the KeePass process so plugin breakpoints are hit.
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$DebugProvider,
    [switch]$DebugPlugin
)

# The launch profiles run this through conhost.exe so it gets its own console window; no relaunch here.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Shared.psm1" -Force

$RepoRoot = Split-Path $PSScriptRoot -Parent

# Enumerates running Visual Studio (DTE) instances from the COM Running Object Table. Version-agnostic:
# matches any "!VisualStudio.DTE..." moniker rather than probing a fixed list of version progIds.
if (-not ([System.Management.Automation.PSTypeName]'VsRot').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class VsRot
{
    [DllImport("ole32.dll")] static extern int GetRunningObjectTable(uint reserved, out IRunningObjectTable prot);
    [DllImport("ole32.dll")] static extern int CreateBindCtx(uint reserved, out IBindCtx ppbc);

    public static object[] GetDtes()
    {
        // Out variables are declared up front because Add-Type on Windows PowerShell 5.1 uses a
        // pre-C# 7 compiler that does not support inline "out var" declarations.
        var found = new List<object>();
        IRunningObjectTable rot;
        if (GetRunningObjectTable(0, out rot) != 0) return found.ToArray();
        IBindCtx ctx;
        CreateBindCtx(0, out ctx);
        IEnumMoniker monikers;
        rot.EnumRunning(out monikers);
        monikers.Reset();
        var one = new IMoniker[1];
        while (monikers.Next(1, one, IntPtr.Zero) == 0)
        {
            string name;
            try { one[0].GetDisplayName(ctx, null, out name); } catch { name = ""; }
            object obj;
            if (name != null && name.StartsWith("!VisualStudio.DTE", StringComparison.Ordinal)
                && rot.GetObject(one[0], out obj) == 0)
            {
                found.Add(obj);
            }
        }
        return found.ToArray();
    }
}
'@
}

# Attaches a running Visual Studio to a process by id. Best-effort: retries while VS is busy or the
# target has not yet appeared in the debugger's process list.
function Connect-VisualStudioDebugger([int]$TargetProcessId) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        foreach ($dte in [VsRot]::GetDtes()) {
            try {
                foreach ($proc in $dte.Debugger.LocalProcesses) {
                    if ($proc.ProcessID -eq $TargetProcessId) {
                        $proc.Attach()
                        return $true
                    }
                }
            } catch {
                # VS busy (RPC_E_CALL_REJECTED) or process list not ready yet; fall through and retry.
            }
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

Write-Step "Building KeePassPasskey plugin DLL"
Invoke-BuildPlugin -RepoRoot $RepoRoot -Configuration $Configuration

& "$PSScriptRoot\Install-Provider.ps1" -Configuration $Configuration

# Start the just-installed provider
$subject = Get-CertSubject $Configuration
$pkg = Get-AppxPackage -Name 'KeePassPasskeyProvider' |
       Where-Object { $_.Publisher -eq $subject } |
       Select-Object -First 1
if ($pkg) {
    $exe = Join-Path $pkg.InstallLocation 'KeePassPasskeyProvider\KeePassPasskeyProvider.exe'
    if (Test-Path $exe) {
        $providerProc = Start-Process $exe -PassThru
        if ($DebugProvider) {
            Write-Host "Attaching Visual Studio to the provider (PID $($providerProc.Id))..."
            if (Connect-VisualStudioDebugger -TargetProcessId $providerProc.Id) {
                Write-Host "  Attached to provider."
            } else {
                Write-Warning "  Could not attach Visual Studio to the provider."
            }
        }
    }
} else {
    Write-Warning "Provider package not found after install; skipping provider launch."
}

# Give the provider time to start up before KeePass launches.
Start-Sleep -Seconds 5

$keepass = Join-Path $RepoRoot 'build\KeePass\KeePass.exe'
if (-not (Test-Path $keepass)) { throw "KeePass not found: $keepass" }
$keepassProc = Start-Process $keepass -PassThru

if ($DebugPlugin) {
    Write-Host "Attaching Visual Studio to KeePass (PID $($keepassProc.Id))..."
    if (Connect-VisualStudioDebugger -TargetProcessId $keepassProc.Id) {
        Write-Host "  Attached to KeePass."
    } else {
        Write-Warning "  Could not attach Visual Studio to KeePass."
    }
}

# Brief pause so the attach status above stays readable before this console window closes.
Start-Sleep -Seconds 5
