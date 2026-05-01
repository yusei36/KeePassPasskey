using KeePassPasskeyShared;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyProvider.Util;

[Flags]
public enum UserVerificationMode
{
    None         = 0,
    WindowsHello = 1,
    Notification = 2,
    Both         = WindowsHello | Notification,
}

internal sealed class AppSettings
{
    internal static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "KeePassPasskeyProvider");

    [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
    public LogLevel LogLevel { get; init; } = LogLevel.Debug;
#else
    public LogLevel LogLevel { get; init; } = LogLevel.Info;
#endif

    public bool ShowErrorNotifications { get; init; } = true;

    public int NotificationVerificationTimeoutSeconds { get; init; } = 30;

    [JsonConverter(typeof(StringEnumConverter))]
    public UserVerificationMode RegistrationVerification { get; init; } = UserVerificationMode.Notification;

    [JsonConverter(typeof(StringEnumConverter))]
    public UserVerificationMode SignInVerification { get; init; } = UserVerificationMode.Notification;

    public static AppSettings Current { get; } = Load();

    private static AppSettings Load()
    {
        string path = Path.Combine(ConfigDir, "AppSettings.json");
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
