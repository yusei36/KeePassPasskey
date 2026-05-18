// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

/// <summary>
/// Provider-UI-only settings that are not synced to or from KeePass.
/// </summary>
internal sealed class LocalProviderSettings
{
    internal static LocalProviderSettings Current { get; set; } = new();

    private static readonly string FilePath = Path.Combine(
        SettingsCache.SettingsDir, "LocalSettings.json");

    [JsonProperty("enableTrayIcon")]
    internal bool EnableTrayIcon { get; set; }

    [JsonProperty("trayIconPromptShown")]
    internal bool TrayIconPromptShown { get; set; }

    internal static LocalProviderSettings? TryLoad()
    {
        try
        {
            if (!File.Exists(FilePath))
                return null;
            return JsonConvert.DeserializeObject<LocalProviderSettings>(File.ReadAllText(FilePath));
        }
        catch
        {
            return null;
        }
    }

    internal static void Save(LocalProviderSettings settings)
    {
        try
        {
            Directory.CreateDirectory(SettingsCache.SettingsDir);
            string tmp = FilePath + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(tmp, JsonConvert.SerializeObject(settings, Formatting.Indented));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"LocalProviderSettings.Save failed: {ex.Message}");
        }
    }
}
