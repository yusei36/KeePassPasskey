// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey;

internal sealed class ProviderPackage
{
	internal string PackageFamilyName;
	internal string ChannelDisplayName;
	internal string InstallPath;

	internal string ProviderExePath => Path.Combine(InstallPath, ProviderPackageLocator.ProviderExeRelativePath);
	internal string BundledPluginDllPath => Path.Combine(InstallPath, ProviderPackageLocator.PluginDllRelativePath);
	internal string InstallScriptPath => Path.Combine(InstallPath, PluginInstallLauncher.ScriptRelativePath);

	internal string BundledPluginVersion
	{
		get
		{
			try
			{
				return File.Exists(BundledPluginDllPath)
					? FileVersionInfo.GetVersionInfo(BundledPluginDllPath).ProductVersion
					: null;
			}
			catch { return null; }
		}
	}
}

/// <summary>
/// Finds the installed provider packages and the files they ship. The plugin has no package identity
/// of its own, so it enumerates by Package Family Name instead of asking for its own location.
/// </summary>
internal static class ProviderPackageLocator
{
	internal const string ProviderExeRelativePath = @"KeePassPasskeyProvider\KeePassPasskeyProvider.exe";
	internal const string PluginDllRelativePath = @"KeePassPasskeyPlugin\KeePassPasskey.dll";

	// PFNs are deterministic from the manifest Name + Publisher, so these are stable (including the
	// Debug one). Keep in sync with ClientVerifier and PluginConstants.OfficialPackageFamilyNames.
	private static readonly KeyValuePair<string, string>[] KnownChannels =
	{
#if DEBUG
		new KeyValuePair<string, string>("KeePassPasskeyProvider_hdweypz22wfyt", "Dev"),
#else
		new KeyValuePair<string, string>("KeePassPasskeyProvider_rcm79ea08mqe4", "GitHub"),
		new KeyValuePair<string, string>("51133UweKgel.KeePassPasskey_2xyhjw5z6d8g4", "Microsoft Store"),
#endif
	};

	internal static bool IsOfficialPackageFamilyName(string packageFamilyName)
	{
		foreach (var channel in KnownChannels)
			if (string.Equals(channel.Key, packageFamilyName, StringComparison.OrdinalIgnoreCase))
				return true;
		return false;
	}

	internal static List<ProviderPackage> FindInstalledPackages(Action<string> onWarn = null)
	{
		var packages = new List<ProviderPackage>();
		foreach (var channel in KnownChannels)
		{
			foreach (string fullName in FindPackageFullNames(channel.Key, onWarn))
			{
				string installPath = GetPackagePath(fullName, onWarn);
				if (string.IsNullOrEmpty(installPath))
					continue;

				packages.Add(new ProviderPackage
				{
					PackageFamilyName = channel.Key,
					ChannelDisplayName = channel.Value,
					InstallPath = installPath,
				});
			}
		}
		return packages;
	}

	// Both Release channels can be installed side by side and can lag each other, so pick by
	// bundled version rather than by enumeration order.
	internal static ProviderPackage FindNewestBundledPlugin(Action<string> onWarn = null)
	{
		ProviderPackage best = null;
		string bestVersion = null;
		foreach (var package in FindInstalledPackages(onWarn))
		{
			string version = package.BundledPluginVersion;
			if (version == null)
				continue;
			if (best == null || PipeConstants.CompareProductVersions(version, bestVersion) > 0)
			{
				best = package;
				bestVersion = version;
			}
		}
		return best;
	}

	internal static ProviderPackage FindByPackageFamilyName(string packageFamilyName, Action<string> onWarn = null)
	{
		if (!IsOfficialPackageFamilyName(packageFamilyName))
			return null;
		foreach (var package in FindInstalledPackages(onWarn))
			if (string.Equals(package.PackageFamilyName, packageFamilyName, StringComparison.OrdinalIgnoreCase))
				return package;
		return null;
	}

	private static string[] FindPackageFullNames(string packageFamilyName, Action<string> onWarn)
	{
		try
		{
			uint count = 0, bufferLength = 0;
			int rc = FindPackagesByPackageFamily(packageFamilyName, PACKAGE_FILTER_HEAD,
				ref count, null, ref bufferLength, IntPtr.Zero, null);
			if (count == 0)
				return new string[0];
			if (rc != ERROR_INSUFFICIENT_BUFFER)
			{
				onWarn?.Invoke("FindPackagesByPackageFamily sizing failed for " + packageFamilyName + " rc=" + rc);
				return new string[0];
			}

			var fullNamePtrs = new IntPtr[count];
			IntPtr buffer = Marshal.AllocHGlobal((int)bufferLength * sizeof(char));
			try
			{
				rc = FindPackagesByPackageFamily(packageFamilyName, PACKAGE_FILTER_HEAD,
					ref count, fullNamePtrs, ref bufferLength, buffer, null);
				if (rc != ERROR_SUCCESS)
				{
					onWarn?.Invoke("FindPackagesByPackageFamily failed for " + packageFamilyName + " rc=" + rc);
					return new string[0];
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
			onWarn?.Invoke("provider enumeration failed for " + packageFamilyName + ": " + ex.Message);
			return new string[0];
		}
	}

	private static string GetPackagePath(string packageFullName, Action<string> onWarn)
	{
		uint length = 0;
		int rc = GetPackagePathByFullName(packageFullName, ref length, null);
		if (rc != ERROR_INSUFFICIENT_BUFFER)
		{
			onWarn?.Invoke("GetPackagePathByFullName sizing failed for " + packageFullName + " rc=" + rc);
			return null;
		}

		var sb = new StringBuilder((int)length);
		rc = GetPackagePathByFullName(packageFullName, ref length, sb);
		if (rc != ERROR_SUCCESS)
		{
			onWarn?.Invoke("GetPackagePathByFullName failed for " + packageFullName + " rc=" + rc);
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
}
