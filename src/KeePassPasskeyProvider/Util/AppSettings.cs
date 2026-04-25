using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyProvider.Util;

internal sealed class AppSettings
{
    internal static readonly string ConfigDir = GetConfigDir();

    private static string GetConfigDir()
    {
        try
        {
            // When MSIX-packaged, ApplicationData.Current.LocalFolder.Path returns the real physical
            // package path (%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local), not the virtual one.
            return Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "KeePassPasskeyProvider");
        }
        catch
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KeePassPasskeyProvider");
        }
    }

    [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
    public LogLevel LogLevel { get; init; } = LogLevel.Debug;
#else
    public LogLevel LogLevel { get; init; } = LogLevel.Info;
#endif

    public bool ShowErrorNotifications { get; init; } = true;

    public bool RequireUserVerificationForRegistration { get; init; } = true;

    public bool RequireUserVerificationForSignIn { get; init; } = true;

    public static AppSettings Current { get; } = Load();

    private static AppSettings Load()
    {
        string path = Path.Combine(ConfigDir, "appsettings.json");
        try
        {
            if (!File.Exists(path))
            {
                var defaultAppSettings = new AppSettings();
                Directory.CreateDirectory(ConfigDir);
                File.WriteAllText(path, JsonConvert.SerializeObject(defaultAppSettings, Formatting.Indented));
                return defaultAppSettings;
            }

            string json = File.ReadAllText(path);
            return JsonConvert.DeserializeObject<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }
}
