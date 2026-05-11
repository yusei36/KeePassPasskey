// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Kögel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

internal static class SettingsCache
{
    internal static readonly string SettingsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KeePassPasskeyProvider");

    internal const string SettingsFileName = "Settings.cached.json";

    private static readonly string CachePath = Path.Combine(SettingsDir, SettingsFileName);

    internal static KeePassPasskeySettings? TryLoad()
    {
        try
        {
            if (!File.Exists(CachePath))
                return null;
            string json = File.ReadAllText(CachePath);
            return JsonConvert.DeserializeObject<KeePassPasskeySettings>(json);
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
            Directory.CreateDirectory(SettingsDir);
            string tmp = CachePath + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(tmp, JsonConvert.SerializeObject(settings, Formatting.Indented));
            File.Move(tmp, CachePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"SettingsCache.Save failed: {ex.Message}");
        }
    }
}
