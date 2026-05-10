using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Config
{
    public class KeePassPasskeyConfig
    {
        public static KeePassPasskeyConfig Current { get; set; } = new KeePassPasskeyConfig();

        [JsonProperty("registrationVerification")]
        public UserVerificationMode RegistrationVerification { get; set; } = UserVerificationMode.Notification;

        [JsonProperty("signInVerification")]
        public UserVerificationMode SignInVerification { get; set; } = UserVerificationMode.Notification;

        [JsonProperty("showErrorNotifications")]
        public bool ShowErrorNotifications { get; set; } = true;

        [JsonProperty("notificationVerificationTimeoutMilliseconds")]
        public int NotificationVerificationTimeoutMilliseconds { get; set; } = 30_000;

        [JsonProperty("logLevel")]
        [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
        public LogLevel LogLevel { get; set; } = LogLevel.Debug;
#else
        public LogLevel LogLevel { get; set; } = LogLevel.Info;
#endif

        [JsonProperty("configSyncIntervalMilliseconds")]
        public int ConfigSyncIntervalMilliseconds { get; set; } = 30_000;

        [JsonProperty("credentialSyncIntervalMilliseconds")]
        public int CredentialSyncIntervalMilliseconds { get; set; } = 30_000;

        [JsonProperty("statusRefreshIntervalMilliseconds")]
        public int StatusRefreshIntervalMilliseconds { get; set; } = 30_000;

        [JsonProperty("credentialSyncShutdownThreshold")]
        public int CredentialSyncShutdownThreshold { get; set; } = 10;

        // JSON-based comparison keeps Equals auto-maintaining: new fields are included
        // automatically without needing to update this method. If performance ever becomes
        // a concern, replace with explicit field-by-field comparison.
        public override bool Equals(object obj)
        {
            if (obj is not KeePassPasskeyConfig other) return false;
            return JsonConvert.SerializeObject(this) == JsonConvert.SerializeObject(other);
        }

        public override int GetHashCode() => JsonConvert.SerializeObject(this).GetHashCode();
    }
}
