using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyProvider.Util;

internal sealed class AppSettings
{
    internal static readonly string ConfigDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     "KeePassPasskeyProvider");

    [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
    public LogLevel LogLevel { get; init; } = LogLevel.Debug;
#else
    public LogLevel LogLevel { get; init; } = LogLevel.Info;
#endif

    public bool ShowErrorNotifications { get; init; } = true;

    public static AppSettings Current { get; } = Load();

    private static AppSettings Load()
    {
        string path = Path.Combine(ConfigDir, "appsettings.json");
        try
        {
            if (!File.Exists(path))
                return new AppSettings();

            string json = File.ReadAllText(path);
            return JsonConvert.DeserializeObject<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }
}
