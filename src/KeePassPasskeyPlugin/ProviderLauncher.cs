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
/// Launches the installed KeePassPasskey provider(s), either to refresh the Windows credential cache
/// (<c>/synccredential</c>) or to open the app (<c>/settings</c>). The provider is the only process
/// with the MSIX package identity required to write that cache.
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
internal static class ProviderLauncher
{
	/// <summary>Launches <c>/synccredential</c> on the appropriate installed provider(s).</summary>
	internal static void LaunchSync()
	{
#if DEBUG
		LaunchViaAlias("/synccredential");
#else
		LaunchOnAllInstalledPackages();
#endif
	}

	/// <summary>Opens the app on its Settings page. Unlike the cache sync this targets one package:
	/// two windows would be no more useful than one, and the provider itself brings a running
	/// instance forward rather than starting a second. The newest one wins, and an even match goes
	/// to the Store package, which is the half that updates itself.</summary>
	internal static bool LaunchSettings()
	{
#if DEBUG
		return LaunchViaAlias("/settings");
#else
		var package = ProviderPackageLocator.FindNewestBundledPlugin(m => Log.Warn(m))
			?? ProviderPackageLocator.FindPreferredPackage(m => Log.Warn(m));
		return package != null && Launch(package.ProviderExePath, "/settings", package.PackageFamilyName);
#endif
	}

#if DEBUG
	private const string DevProviderAlias = "KeePassPasskeyProviderDev.exe";

	private static bool LaunchViaAlias(string arguments)
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = DevProviderAlias,
				Arguments = arguments,
				UseShellExecute = false,
				CreateNoWindow = true,
			});
			Log.Debug("launched " + DevProviderAlias + " " + arguments);
			return true;
		}
		catch (Exception ex)
		{
			Log.Warn("failed to launch provider (" + DevProviderAlias + " " + arguments + "): " + ex.Message);
			return false;
		}
	}
#else
	private static void LaunchOnAllInstalledPackages()
	{
		int launched = 0;
		foreach (var package in ProviderPackageLocator.FindInstalledPackages(m => Log.Warn(m)))
			if (Launch(package.ProviderExePath, "/synccredential", package.PackageFamilyName))
				launched++;

		if (launched == 0)
			Log.Debug("no installed provider package found to sync");
	}

	private static bool Launch(string exe, string arguments, string packageFamilyName)
	{
		try
		{
			if (!File.Exists(exe))
			{
				Log.Warn("provider exe not found: " + exe);
				return false;
			}

			Process.Start(new ProcessStartInfo
			{
				FileName = exe,
				Arguments = arguments,
				UseShellExecute = false,
				CreateNoWindow = true,
			});
			Log.Debug("launched provider " + arguments + ": " + exe);
			return true;
		}
		catch (Exception ex)
		{
			Log.Warn("failed to launch provider " + arguments + " (" + packageFamilyName + "): " + ex.Message);
			return false;
		}
	}
#endif
}
