// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace KeePassPasskey.Update;

/// <summary>Where the loaded plugin DLL sits, which is where an update has to be written.</summary>
internal static class PluginLocation
{
	/// <summary>Path of the loaded plugin DLL, or null when it cannot be updated in place.</summary>
	internal static string DllPath { get; } = ResolveDllPath();

	internal static string DirectoryPath =>
		DllPath == null ? null : Path.GetDirectoryName(DllPath);

	// Read off the file rather than the assembly attribute, so it is obtained the same way as the
	// bundled version it gets compared against.
	internal static string InstalledVersion
	{
		get
		{
			try
			{
				return DllPath == null ? null : FileVersionInfo.GetVersionInfo(DllPath).ProductVersion;
			}
			catch { return null; }
		}
	}

	private static string ResolveDllPath()
	{
		try
		{
			string location = Assembly.GetExecutingAssembly().Location;
			if (string.IsNullOrEmpty(location) || !File.Exists(location))
				return null;

			// A .plgx is compiled into KeePass's plugin cache, so the loaded file is a build
			// artefact and overwriting it would be undone on the next cache rebuild.
			if (location.IndexOf(@"\PluginCache\", StringComparison.OrdinalIgnoreCase) >= 0)
				return null;

			return location;
		}
		catch
		{
			return null;
		}
	}
}
