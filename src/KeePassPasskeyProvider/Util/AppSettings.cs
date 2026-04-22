using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyProvider.Util;

internal sealed class AppSettings
{
    [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
    public LogLevel LogLevel { get; init; } = LogLevel.Debug;
#else
    public LogLevel LogLevel { get; init; } = LogLevel.Info;
#endif

    public static AppSettings Load(string directory)
    {
        string path = Path.Combine(directory, "appsettings.json");
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
