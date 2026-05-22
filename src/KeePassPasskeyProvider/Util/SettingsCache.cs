// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

internal static class SettingsCache
{
    internal const string SettingsFileName = "Settings.cached.json";

    private static readonly string CachePath = Path.Combine(AppPaths.SettingsDir, SettingsFileName);

    internal static KeePassPasskeySettings? TryLoad()
    {
        try
        {
            if (!File.Exists(CachePath))
                return null;
            var settings = JsonConvert.DeserializeObject<KeePassPasskeySettings>(File.ReadAllText(CachePath));
            if (settings != null && Log.LogFilePath != null)
                Log.Configure(Log.LogFilePath, settings.LogLevel);
            return settings;
        }
        catch
        {
            return null;
        }
    }

    internal static void Save(KeePassPasskeySettings settings)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.SettingsDir);
            string tmp = CachePath + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(tmp, JsonConvert.SerializeObject(settings, Formatting.Indented));
            File.Move(tmp, CachePath, overwrite: true);
            if (Log.LogFilePath != null)
                Log.Configure(Log.LogFilePath, settings.LogLevel);
        }
        catch (Exception ex)
        {
            Log.Warn($"SettingsCache.Save failed: {ex.Message}");
        }
    }
}
