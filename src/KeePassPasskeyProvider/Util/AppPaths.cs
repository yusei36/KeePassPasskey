// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Util;

internal static class AppPaths
{
	/// <summary>Where the plugin writes Plugin.log, and the provider's fallback when unpackaged (dev/CI).</summary>
	internal static readonly string SharedLocalAppDataDir = KeePassPasskeyShared.PluginLogFile.DirectoryPath;

	/// <summary>LocalCache when packaged, else the shared fallback.</summary>
	internal static readonly string LogDir = GetLogDir();

	/// <summary>LocalState when packaged, else the shared fallback.</summary>
	internal static readonly string SettingsDir = GetSettingsDir();

	private static string GetLogDir()
	{
		try
		{
			return Windows.Storage.ApplicationData.Current.LocalCacheFolder.Path;
		}
		catch
		{
			return SharedLocalAppDataDir;
		}
	}

	private static string GetSettingsDir()
	{
		try
		{
			return Windows.Storage.ApplicationData.Current.LocalFolder.Path;
		}
		catch
		{
			return SharedLocalAppDataDir;
		}
	}
}
