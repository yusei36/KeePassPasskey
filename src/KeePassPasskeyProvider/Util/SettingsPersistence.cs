using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

internal static class SettingsPersistence
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
            File.WriteAllText(CachePath, JsonConvert.SerializeObject(settings, Formatting.Indented));
        }
        catch (Exception ex)
        {
            Log.Warn($"SettingsPersistence.Save failed: {ex.Message}");
        }
    }
}
