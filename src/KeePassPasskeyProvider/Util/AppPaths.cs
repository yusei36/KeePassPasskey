// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Util;

internal static class AppPaths
{
    /// <summary>
    /// Always %LOCALAPPDATA%\KeePassPasskeyProvider — used for the log file so it is
    /// accessible outside the MSIX package container.
    /// </summary>
    internal static readonly string LogDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KeePassPasskeyProvider");

    /// <summary>
    /// When running as an MSIX package, the container's LocalState folder;
    /// otherwise falls back to the same directory as LogDir.
    /// </summary>
    internal static readonly string SettingsDir = GetSettingsDir();

    private static string GetSettingsDir()
    {
        try
        {
            return Windows.Storage.ApplicationData.Current.LocalFolder.Path;
        }
        catch
        {
            return LogDir;
        }
    }
}
