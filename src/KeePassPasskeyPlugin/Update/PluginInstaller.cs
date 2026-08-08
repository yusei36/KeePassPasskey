// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace KeePassPasskey.Update;

internal enum PluginInstallResult
{
	Success = 0,
	AccessDenied = 2,
	SourceMissing = 3,
	TargetInvalid = 4,
	Failed = 5,
}

/// <summary>
/// Installs, updates and removes the plugin DLL. Dependency-free so the elevation helper can link
/// this source file rather than duplicate it.
///
/// A loaded DLL cannot be deleted but can be renamed, so an update moves the old file aside to
/// <c>.old</c> and writes the new one under the original name; KeePass runs on the old image until
/// it restarts, and the leftover is deleted at the next plugin start.
/// </summary>
internal static class PluginInstaller
{
	internal const string PluginDllName = "KeePassPasskey.dll";
	internal const string BackupSuffix = ".old";

	internal static PluginInstallResult Install(string sourceDll, string targetDirectory, out string error)
	{
		error = null;

		if (string.IsNullOrEmpty(sourceDll) || !File.Exists(sourceDll))
		{
			error = "Bundled plugin not found: " + sourceDll;
			return PluginInstallResult.SourceMissing;
		}
		if (string.IsNullOrEmpty(targetDirectory))
		{
			error = "No target folder given.";
			return PluginInstallResult.TargetInvalid;
		}

		string target = Path.Combine(targetDirectory, PluginDllName);
		string backup = target + BackupSuffix;
		bool movedAside = false;

		try
		{
			if (!Directory.Exists(targetDirectory))
				Directory.CreateDirectory(targetDirectory);

			DeleteIfPresent(backup);

			if (File.Exists(target))
			{
				File.Move(target, backup);
				movedAside = true;
			}

			File.Copy(sourceDll, target, true);
			return PluginInstallResult.Success;
		}
		catch (Exception ex)
		{
			if (movedAside)
				TryRestore(backup, target);
			error = ex.Message;
			return Classify(ex);
		}
	}

	internal static PluginInstallResult Remove(string targetDirectory, out string error)
	{
		error = null;

		if (string.IsNullOrEmpty(targetDirectory) || !Directory.Exists(targetDirectory))
		{
			error = "Folder not found: " + targetDirectory;
			return PluginInstallResult.TargetInvalid;
		}

		string target = Path.Combine(targetDirectory, PluginDllName);
		if (!File.Exists(target))
			return PluginInstallResult.Success;

		try
		{
			DeleteIfPresent(target);
			DeleteIfPresent(target + BackupSuffix);
			return PluginInstallResult.Success;
		}
		catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException)
		{
			// Loaded by a running KeePass: rename it out of the way so it is not picked up again,
			// and let the reboot finish the deletion.
			try
			{
				string backup = target + BackupSuffix;
				DeleteIfPresent(backup);
				File.Move(target, backup);
				MoveFileEx(backup, null, MOVEFILE_DELAY_UNTIL_REBOOT);
				return PluginInstallResult.Success;
			}
			catch (Exception inner)
			{
				error = inner.Message;
				return Classify(inner);
			}
		}
		catch (Exception ex)
		{
			error = ex.Message;
			return Classify(ex);
		}
	}

	internal static void CleanUpBackup(string targetDirectory)
	{
		if (string.IsNullOrEmpty(targetDirectory)) return;
		try { DeleteIfPresent(Path.Combine(targetDirectory, PluginDllName + BackupSuffix)); }
		catch { }
	}

	internal static bool CanWriteTo(string targetDirectory)
	{
		try
		{
			if (!Directory.Exists(targetDirectory)) return false;
			string probe = Path.Combine(targetDirectory, "." + Guid.NewGuid().ToString("N") + ".tmp");
			using (File.Create(probe)) { }
			File.Delete(probe);
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static void DeleteIfPresent(string path)
	{
		if (File.Exists(path))
			File.Delete(path);
	}

	private static void TryRestore(string backup, string target)
	{
		try
		{
			if (File.Exists(backup) && !File.Exists(target))
				File.Move(backup, target);
		}
		catch { }
	}

	private static PluginInstallResult Classify(Exception ex) =>
		ex is UnauthorizedAccessException ? PluginInstallResult.AccessDenied : PluginInstallResult.Failed;

	private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern bool MoveFileEx(string existingFileName, string newFileName, uint flags);
}
