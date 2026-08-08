// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Diagnostics;
#if !DEBUG
using System.IO;
#endif
using KeePassPasskeyShared;

namespace KeePassPasskey;

/// <summary>
/// Launches the installed KeePassPasskey provider(s) to refresh the Windows credential cache
/// (<c>/synccredential</c>). The provider is the only process with the MSIX package identity
/// required to write that cache.
///
/// Debug (dev identity) launches the single dev provider via its dedicated app-execution alias:
/// the dev alias never collides with a Release install.
///
/// Release must refresh every installed channel (GitHub + Store), each of which keeps its own
/// per-CLSID cache, or the other channel's sign-in surfaces no passkeys. The two Release channels
/// share one app-execution alias, so Release cannot use it to target a specific provider; instead
/// it enumerates the installed provider packages and launches each by full install path.
/// Launching the packaged full-trust exe by full path still confers package identity (verified).
/// </summary>
internal static class ProviderSyncLauncher
{
	/// <summary>Launches <c>/synccredential</c> on the appropriate installed provider(s).</summary>
	internal static void LaunchSync()
	{
#if DEBUG
		LaunchViaAlias(DevProviderAlias);
#else
		LaunchOnAllInstalledPackages();
#endif
	}

#if DEBUG
	private const string DevProviderAlias = "KeePassPasskeyProviderDev.exe";

	private static void LaunchViaAlias(string alias)
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = alias,
				Arguments = "/synccredential",
				UseShellExecute = false,
				CreateNoWindow = true,
			});
			Log.Debug("launched " + alias + " /synccredential");
		}
		catch (Exception ex)
		{
			Log.Warn("failed to launch provider sync (" + alias + "): " + ex.Message);
		}
	}
#else
	private static void LaunchOnAllInstalledPackages()
	{
		int launched = 0;
		foreach (var package in ProviderPackageLocator.FindInstalledPackages(m => Log.Warn(m)))
		{
			try
			{
				string exe = package.ProviderExePath;
				if (!File.Exists(exe))
				{
					Log.Warn("provider exe not found: " + exe);
					continue;
				}

				Process.Start(new ProcessStartInfo
				{
					FileName = exe,
					Arguments = "/synccredential",
					UseShellExecute = false,
					CreateNoWindow = true,
				});
				launched++;
				Log.Debug("launched provider sync: " + exe);
			}
			catch (Exception ex)
			{
				Log.Warn("failed to launch provider sync (" + package.PackageFamilyName + "): " + ex.Message);
			}
		}

		if (launched == 0)
			Log.Debug("no installed provider package found to sync");
	}
#endif
}
