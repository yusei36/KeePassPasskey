// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

internal sealed class AppSettings
{
    internal static AppSettings Current { get; set; } = new();

    private static readonly string FilePath = Path.Combine(
        AppPaths.SettingsDir, "AppSettings.json");

    [JsonProperty("enableTrayIcon")]
    internal bool EnableTrayIcon { get; set; }

    [JsonProperty("trayIconPromptShown")]
    internal bool TrayIconPromptShown { get; set; }

    [JsonProperty("theme")]
    internal Theme Theme { get; set; } = Theme.System;

    internal static AppSettings? TryLoad()
    {
        try
        {
            if (!File.Exists(FilePath))
                return null;
            return JsonConvert.DeserializeObject<AppSettings>(File.ReadAllText(FilePath));
        }
        catch
        {
            return null;
        }
    }

    internal static void Save(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.SettingsDir);
            string tmp = FilePath + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(tmp, JsonConvert.SerializeObject(settings, Formatting.Indented));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"AppSettings.Save failed: {ex.Message}");
        }
    }
}
