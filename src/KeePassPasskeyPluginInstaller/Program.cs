// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.Installer;

/// <summary>
/// Elevation helper for installing the plugin DLL, launched with <c>runas</c> by the plugin and by
/// the provider app only after a direct write was denied.
///
/// It runs elevated on behalf of a medium-integrity caller and copies code into a password manager,
/// so it trusts no argument: the source is not passed in but resolved here from the installed
/// official packages (which sit under WindowsApps and are not user-writable), the destination must
/// look like a KeePass installation, and the written file name is fixed.
/// </summary>
internal static class Program
{
	[STAThread]
	private static int Main(string[] args)
	{
		try
		{
			var result = Run(args, out string error);
			return result == PluginInstallResult.Success ? 0 : Fail((int)result, error);
		}
		catch (Exception ex)
		{
			return Fail((int)PluginInstallResult.Failed, ex.ToString());
		}
	}

	private static PluginInstallResult Run(string[] args, out string error)
	{
		error = null;

		string action = null, target = null, package = null;
		for (int i = 0; i < args.Length; i++)
		{
			switch (args[i])
			{
				case "--install":
				case "--remove":
					action = args[i];
					break;
				case "--target":
					target = ++i < args.Length ? args[i] : null;
					break;
				case "--package":
					package = ++i < args.Length ? args[i] : null;
					break;
			}
		}

		if (action == null)
		{
			error = "Usage: --install --target <dir> [--package <pfn>] | --remove --target <dir>";
			return PluginInstallResult.TargetInvalid;
		}

		target = NormalizeTarget(target);
		if (target == null || !LooksLikeKeePassPluginFolder(target))
		{
			error = "Refusing to write to a folder that is not part of a KeePass installation: " + target;
			return PluginInstallResult.TargetInvalid;
		}

		if (action == "--remove")
			return PluginInstaller.Remove(target, out error);

		var source = ResolveSource(package);
		if (source == null)
		{
			error = "No installed KeePassPasskey package ships a plugin DLL.";
			return PluginInstallResult.SourceMissing;
		}

		return PluginInstaller.Install(source.BundledPluginDllPath, target, out error);
	}

	// The caller's --package is only a hint: it selects among packages this process found itself,
	// so it is not a trust decision.
	private static ProviderPackage ResolveSource(string packageFamilyName)
	{
		if (!string.IsNullOrEmpty(packageFamilyName))
		{
			var named = ProviderPackageLocator.FindByPackageFamilyName(packageFamilyName);
			if (named != null && File.Exists(named.BundledPluginDllPath))
				return named;
		}

		var newest = ProviderPackageLocator.FindNewestBundledPlugin();
		return newest != null && File.Exists(newest.BundledPluginDllPath) ? newest : null;
	}

	private static string NormalizeTarget(string target)
	{
		if (string.IsNullOrWhiteSpace(target)) return null;
		try
		{
			return Path.GetFullPath(target.Trim().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
		}
		catch
		{
			return null;
		}
	}

	// KeePass.exe in the folder, its parent or its grandparent covers a portable layout as well as
	// Plugins\ and Plugins\KeePassPasskeyPlugin\. The folder itself need not exist yet.
	private static bool LooksLikeKeePassPluginFolder(string target)
	{
		string candidate = target;
		for (int level = 0; level < 3 && candidate != null; level++)
		{
			if (File.Exists(Path.Combine(candidate, "KeePass.exe")))
				return true;
			candidate = Path.GetDirectoryName(candidate);
		}
		return false;
	}

	// "runas" requires ShellExecute, so the caller cannot read stdout and only sees the exit code.
	private static int Fail(int code, string message)
	{
		try
		{
			File.AppendAllText(
				Path.Combine(Path.GetTempPath(), "KeePassPasskeyPluginInstaller.log"),
				DateTime.Now.ToString("s") + " exit=" + code + " " + message + Environment.NewLine);
		}
		catch { }
		return code;
	}
}
