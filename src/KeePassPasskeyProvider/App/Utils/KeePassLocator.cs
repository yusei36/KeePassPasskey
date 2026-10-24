// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.Text.RegularExpressions;
using KeePassPasskeyShared;
using Microsoft.Win32;

namespace KeePassPasskeyProvider.App.Utils;

internal sealed record KeePassLocation(string Directory, string Source);

/// <summary>
/// Finds a KeePass installation to install the plugin into. Sources are tried in descending order of
/// certainty; the one that hit is shown in the dialog so a wrong guess is visible rather than silent.
/// </summary>
internal static class KeePassLocator
{
	private const string KeePassExe = "KeePass.exe";
	private const string PluginsFolder = "Plugins";

	/// <summary>Folder the running plugin loaded from, learned from the ping. Null when not connected.</summary>
	internal static string? ReportedPluginPath { get; set; }

	internal static KeePassLocation? Locate()
	{
		foreach (var candidate in Candidates())
		{
			if (candidate != null && IsKeePassDirectory(candidate.Directory))
				return candidate;
		}
		return null;
	}

	private static IEnumerable<KeePassLocation?> Candidates()
	{
		yield return FromReportedPluginPath();
		yield return FromRunningProcess();
		yield return FromUninstallKey();
		yield return FromInstallerComponents();
		yield return FromConventionalPath();
	}

	/// <summary>
	/// Folder the DLL is written to: the KeePass installation itself, or anything at or below its
	/// Plugins folder. Null when the picked folder is neither.
	/// </summary>
	internal static string? ResolveTargetDirectory(string? folder)
	{
		if (string.IsNullOrWhiteSpace(folder)) return null;

		string directory = folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		if (directory.Length == 0) return null;

		if (IsKeePassDirectory(directory))
			return Path.Combine(directory, PluginsFolder);

		for (string? dir = directory; dir != null; dir = Path.GetDirectoryName(dir))
			if (IsPluginsFolder(dir) && IsKeePassDirectory(Path.GetDirectoryName(dir)))
				return directory;

		return null;
	}

	internal static bool IsKeePassDirectory(string? directory) =>
		!string.IsNullOrWhiteSpace(directory) && File.Exists(Path.Combine(directory, KeePassExe));

	private static bool IsPluginsFolder(string? directory) =>
		directory != null &&
		string.Equals(Path.GetFileName(directory), PluginsFolder, StringComparison.OrdinalIgnoreCase);

	// The reported path is the plugin's own folder, so walk up to the one holding KeePass.exe.
	private static KeePassLocation? FromReportedPluginPath()
	{
		string? directory = ReportedPluginPath;
		for (int level = 0; level < 3 && !string.IsNullOrEmpty(directory); level++)
		{
			if (IsKeePassDirectory(directory))
				return new KeePassLocation(directory, "the running KeePass");
			directory = Path.GetDirectoryName(directory);
		}
		return null;
	}

	private static KeePassLocation? FromRunningProcess()
	{
		try
		{
			foreach (var process in Process.GetProcessesByName("KeePass"))
			{
				using (process)
				{
					string? exe = process.MainModule?.FileName;
					if (exe != null)
						return new KeePassLocation(Path.GetDirectoryName(exe)!, "the running KeePass");
				}
			}
		}
		catch (Exception ex)
		{
			Log.Debug($"KeePass process lookup failed: {ex.Message}");
		}
		return null;
	}

	private static KeePassLocation? FromUninstallKey()
	{
		foreach (var (hive, view, subKey) in UninstallRoots())
		{
			try
			{
				using var root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(subKey);
				string? location = root?.GetValue("InstallLocation") as string;
				if (!string.IsNullOrWhiteSpace(location))
					return new KeePassLocation(location.Trim('"').TrimEnd('\\'), "the KeePass installer's registry entry");
			}
			catch (Exception ex)
			{
				Log.Debug($"uninstall key lookup failed: {ex.Message}");
			}
		}
		return null;
	}

	private static IEnumerable<(RegistryHive, RegistryView, string)> UninstallRoots()
	{
		const string setupKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1";
		yield return (RegistryHive.LocalMachine, RegistryView.Registry32, setupKey);
		yield return (RegistryHive.LocalMachine, RegistryView.Registry64, setupKey);
		yield return (RegistryHive.CurrentUser, RegistryView.Default, setupKey);
	}

	/// <summary>
	/// MSI installs record no InstallLocation, so the path has to come out of the installer's
	/// component database, keyed by the compressed ProductCode.
	/// </summary>
	private static KeePassLocation? FromInstallerComponents()
	{
		try
		{
			string? productCode = FindKeePassProductCode();
			if (productCode == null) return null;

			string? compressed = CompressGuid(productCode);
			if (compressed == null) return null;

			string userSid = WindowsIdentity.GetCurrent().User?.Value ?? "";
			foreach (string userData in new[] { "S-1-5-18", userSid })
			{
				if (string.IsNullOrEmpty(userData)) continue;

				using var components = Registry.LocalMachine.OpenSubKey(
					$@"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\{userData}\Components");
				if (components == null) continue;

				foreach (string componentName in components.GetSubKeyNames())
				{
					using var component = components.OpenSubKey(componentName);
					if (component?.GetValue(compressed) is not string path) continue;
					if (!path.EndsWith(@"\" + KeePassExe, StringComparison.OrdinalIgnoreCase)) continue;

					return new KeePassLocation(Path.GetDirectoryName(path)!, "the MSI installation");
				}
			}
		}
		catch (Exception ex)
		{
			Log.Debug($"MSI component lookup failed: {ex.Message}");
		}
		return null;
	}

	private static string? FindKeePassProductCode()
	{
		var displayName = new Regex(@"^KeePass \d+", RegexOptions.IgnoreCase);
		foreach (var (hive, view, subKey) in ProductRoots())
		{
			using var root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(subKey);
			if (root == null) continue;

			foreach (string productKey in root.GetSubKeyNames())
			{
				if (!productKey.StartsWith('{')) continue;

				using var product = root.OpenSubKey(productKey);
				if (product?.GetValue("DisplayName") is not string name || !displayName.IsMatch(name)) continue;
				if (product.GetValue("Publisher") as string != "Dominik Reichl") continue;

				return productKey;
			}
		}
		return null;
	}

	private static IEnumerable<(RegistryHive, RegistryView, string)> ProductRoots()
	{
		const string uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
		yield return (RegistryHive.LocalMachine, RegistryView.Registry64, uninstall);
		yield return (RegistryHive.LocalMachine, RegistryView.Registry32, uninstall);
		yield return (RegistryHive.CurrentUser, RegistryView.Default, uninstall);
	}

	// MSI keys a component's install path by the ProductCode with each GUID field reversed and the
	// nibbles of every resulting byte swapped.
	private static string? CompressGuid(string productCode)
	{
		if (!Guid.TryParse(productCode, out var guid)) return null;

		var sb = new System.Text.StringBuilder(32);
		foreach (byte b in guid.ToByteArray())
			sb.Append(((b & 0x0F) << 4 | (b & 0xF0) >> 4).ToString("x2", CultureInfo.InvariantCulture));
		return sb.ToString();
	}

	private static KeePassLocation? FromConventionalPath()
	{
		foreach (var folder in new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles })
		{
			string candidate = Path.Combine(Environment.GetFolderPath(folder), "KeePass Password Safe 2");
			if (IsKeePassDirectory(candidate))
				return new KeePassLocation(candidate, "the default install path");
		}
		return null;
	}
}
