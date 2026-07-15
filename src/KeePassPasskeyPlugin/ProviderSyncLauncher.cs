// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Diagnostics;
#if !DEBUG
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
#endif
using KeePassPasskeyShared;

namespace KeePassPasskey;

/// <summary>
/// Launches the installed KeePassPasskey provider(s) to refresh the Windows credential cache
/// (<c>/synccredential</c>). The provider is the only process with the MSIX package identity
/// required to write that cache.
///
/// Debug (dev identity) launches the single dev provider via its dedicated app-execution alias:
/// the dev alias never collides with a Release install, and using the alias keeps it working for
/// every developer regardless of the exact package publisher hash.
///
/// Release must refresh every installed channel (GitHub + Store), each of which keeps its own
/// per-CLSID cache, or the other channel's sign-in surfaces no passkeys. The two Release channels
/// share one app-execution alias, so Release cannot use it to target a specific provider; instead
/// it enumerates the installed provider packages by Package Family Name and launches each by full
/// install path. Launching the packaged full-trust exe by full path still confers package identity
/// (verified).
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
	// Package Family Names of the Release provider packages to refresh. PFNs are deterministic
	// from the manifest Name + Publisher, so these are stable. Keep in sync with ClientVerifier's
	// accepted PFNs and the provider's PluginConstants.OfficialPackageFamilyNames.
	private static readonly string[] ProviderPackageFamilyNames =
	{
		"KeePassPasskeyProvider_rcm79ea08mqe4",       // GitHub channel
		"51133UweKgel.KeePassPasskey_2xyhjw5z6d8g4",  // Store channel
	};

	// Relative path of the provider exe inside its package (constant across channels).
	private const string ProviderExeRelativePath = @"KeePassPasskeyProvider\KeePassPasskeyProvider.exe";

	// Refreshes every installed provider channel by full install path (not the shared alias, which
	// two Release channels would collide on). Missing channels are simply absent from the
	// enumeration; per-package failures are logged and skipped.
	private static void LaunchOnAllInstalledPackages()
	{
		int launched = 0;
		foreach (string pfn in ProviderPackageFamilyNames)
		{
			foreach (string fullName in FindInstalledPackageFullNames(pfn))
			{
				try
				{
					string installPath = GetPackagePath(fullName);
					if (string.IsNullOrEmpty(installPath))
						continue;

					string exe = Path.Combine(installPath, ProviderExeRelativePath);
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
					Log.Warn("failed to launch provider sync (" + fullName + "): " + ex.Message);
				}
			}
		}

		if (launched == 0)
			Log.Debug("no installed provider package found to sync");
	}

	// Returns the full package names installed for the current user under the given family, or
	// an empty array if none are installed.
	private static string[] FindInstalledPackageFullNames(string packageFamilyName)
	{
		try
		{
			uint count = 0, bufferLength = 0;
			int rc = FindPackagesByPackageFamily(packageFamilyName, PACKAGE_FILTER_HEAD,
				ref count, null, ref bufferLength, IntPtr.Zero, null);
			if (count == 0)
				return Array.Empty<string>();
			if (rc != ERROR_INSUFFICIENT_BUFFER)
			{
				Log.Warn("FindPackagesByPackageFamily sizing failed for " + packageFamilyName + " rc=" + rc);
				return Array.Empty<string>();
			}

			var fullNamePtrs = new IntPtr[count];
			IntPtr buffer = Marshal.AllocHGlobal((int)bufferLength * sizeof(char));
			try
			{
				rc = FindPackagesByPackageFamily(packageFamilyName, PACKAGE_FILTER_HEAD,
					ref count, fullNamePtrs, ref bufferLength, buffer, null);
				if (rc != ERROR_SUCCESS)
				{
					Log.Warn("FindPackagesByPackageFamily failed for " + packageFamilyName + " rc=" + rc);
					return Array.Empty<string>();
				}

				var names = new string[count];
				for (int i = 0; i < count; i++)
					names[i] = Marshal.PtrToStringUni(fullNamePtrs[i]);
				return names;
			}
			finally
			{
				Marshal.FreeHGlobal(buffer);
			}
		}
		catch (Exception ex)
		{
			Log.Warn("provider enumeration failed for " + packageFamilyName + ": " + ex.Message);
			return Array.Empty<string>();
		}
	}

	// Returns the install directory of a package by full name, or null on failure.
	private static string GetPackagePath(string packageFullName)
	{
		uint length = 0;
		int rc = GetPackagePathByFullName(packageFullName, ref length, null);
		if (rc != ERROR_INSUFFICIENT_BUFFER)
		{
			Log.Warn("GetPackagePathByFullName sizing failed for " + packageFullName + " rc=" + rc);
			return null;
		}

		var sb = new StringBuilder((int)length);
		rc = GetPackagePathByFullName(packageFullName, ref length, sb);
		if (rc != ERROR_SUCCESS)
		{
			Log.Warn("GetPackagePathByFullName failed for " + packageFullName + " rc=" + rc);
			return null;
		}
		return sb.ToString();
	}

	#region Native Methods

	private const int ERROR_SUCCESS = 0;
	private const int ERROR_INSUFFICIENT_BUFFER = 122;
	private const uint PACKAGE_FILTER_HEAD = 0x00000010;

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
	private static extern int FindPackagesByPackageFamily(string packageFamilyName, uint packageFilters,
		ref uint count, [Out] IntPtr[] packageFullNames, ref uint bufferLength, IntPtr buffer, [Out] uint[] packageProperties);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
	private static extern int GetPackagePathByFullName(string packageFullName, ref uint pathLength, StringBuilder path);

	#endregion
#endif
}
