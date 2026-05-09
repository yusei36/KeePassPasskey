using KeePassPasskeyShared;
using KeePassPasskeyShared.Config;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

internal static class ConfigPersistence
{
    internal static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KeePassPasskeyProvider");

    private static readonly string CachePath = Path.Combine(ConfigDir, "KeePassPasskeyConfig.cached.json");

    internal static KeePassPasskeyConfig? TryLoad()
    {
        try
        {
            if (!File.Exists(CachePath))
                return null;
            string json = File.ReadAllText(CachePath);
            return JsonConvert.DeserializeObject<KeePassPasskeyConfig>(json);
        }
        catch
        {
            return null;
        }
    }

    internal static void Save(KeePassPasskeyConfig config)
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            File.WriteAllText(CachePath, JsonConvert.SerializeObject(config, Formatting.Indented));
        }
        catch (Exception ex)
        {
            Log.Warn($"ConfigPersistence.Save failed: {ex.Message}");
        }
    }
}
