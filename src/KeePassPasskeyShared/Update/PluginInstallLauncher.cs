// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace KeePassPasskeyShared.Update;

public sealed class PluginInstallOutcome
{
	public PluginInstallResult Result { get; set; }
	public string Error { get; set; }

	/// <summary>The elevation prompt was dismissed, which is a decision rather than a failure.</summary>
	public bool Cancelled { get; set; }

	public bool Elevated { get; set; }

	public bool Success => Result == PluginInstallResult.Success;
}

/// <summary>
/// Runs an install or removal, elevating only when the direct write is denied, so portable and
/// per-user KeePass installs never see a UAC prompt.
/// </summary>
public static class PluginInstallLauncher
{
	public static PluginInstallOutcome Install(string sourceDll, string targetDirectory,
		string helperExePath, string packageFamilyName)
	{
		var result = PluginInstaller.Install(sourceDll, targetDirectory, out string error);
		if (result != PluginInstallResult.AccessDenied)
			return new PluginInstallOutcome { Result = result, Error = error };

		string args = "--install --target \"" + targetDirectory + "\"";
		if (!string.IsNullOrEmpty(packageFamilyName))
			args += " --package \"" + packageFamilyName + "\"";
		return RunElevated(helperExePath, args);
	}

	public static PluginInstallOutcome Remove(string targetDirectory, string helperExePath)
	{
		var result = PluginInstaller.Remove(targetDirectory, out string error);
		if (result != PluginInstallResult.AccessDenied)
			return new PluginInstallOutcome { Result = result, Error = error };

		return RunElevated(helperExePath, "--remove --target \"" + targetDirectory + "\"");
	}

	private static PluginInstallOutcome RunElevated(string helperExePath, string arguments)
	{
		if (string.IsNullOrEmpty(helperExePath) || !File.Exists(helperExePath))
		{
			return new PluginInstallOutcome
			{
				Result = PluginInstallResult.SourceMissing,
				Error = "Installer helper not found: " + helperExePath,
			};
		}

		try
		{
			var process = Process.Start(new ProcessStartInfo
			{
				FileName = helperExePath,
				Arguments = arguments,
				UseShellExecute = true,
				Verb = "runas",
				WindowStyle = ProcessWindowStyle.Hidden,
			});
			process.WaitForExit();

			var result = (PluginInstallResult)process.ExitCode;
			return new PluginInstallOutcome
			{
				Result = result,
				Elevated = true,
				Error = result == PluginInstallResult.Success
					? null
					: DescribeExitCode(result),
			};
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == ERROR_CANCELLED)
		{
			return new PluginInstallOutcome
			{
				Result = PluginInstallResult.AccessDenied,
				Cancelled = true,
				Elevated = true,
			};
		}
		catch (Exception ex)
		{
			return new PluginInstallOutcome
			{
				Result = PluginInstallResult.Failed,
				Elevated = true,
				Error = ex.Message,
			};
		}
	}

	private static string DescribeExitCode(PluginInstallResult result)
	{
		switch (result)
		{
			case PluginInstallResult.AccessDenied:
				return "Access to the KeePass plugins folder was denied.";
			case PluginInstallResult.SourceMissing:
				return "The installed KeePassPasskey app does not contain a plugin to install.";
			case PluginInstallResult.TargetInvalid:
				return "The chosen folder is not part of a KeePass installation.";
			default:
				return "The plugin could not be written. See KeePassPasskeyPluginInstaller.log in the temp folder.";
		}
	}

	private const int ERROR_CANCELLED = 1223;
}
