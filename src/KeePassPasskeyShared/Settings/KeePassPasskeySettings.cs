// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings
{
    public class KeePassPasskeySettings
    {
        public static KeePassPasskeySettings Current { get; set; } = new KeePassPasskeySettings();

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

        [JsonProperty("credentialSyncIntervalMilliseconds")]
        public int CredentialSyncIntervalMilliseconds { get; set; } = 30_000;

        [JsonIgnore]
        public bool IsCredentialSyncEnabled => CredentialSyncIntervalMilliseconds > 0;

        [JsonProperty("statusRefreshIntervalMilliseconds")]
        public int StatusRefreshIntervalMilliseconds { get; set; } = 30_000;

        [JsonProperty("credentialSyncShutdownThreshold")]
        public int CredentialSyncShutdownThreshold { get; set; } = 10;

        [JsonProperty("theme")]
        public Theme Theme { get; set; } = Theme.System;

        // JSON-based comparison keeps Equals auto-maintaining: new fields are included
        // automatically without needing to update this method. If performance ever becomes
        // a concern, replace with explicit field-by-field comparison.
        public override bool Equals(object obj)
        {
            if (obj is not KeePassPasskeySettings other) return false;
            return JsonConvert.SerializeObject(this) == JsonConvert.SerializeObject(other);
        }

        public override int GetHashCode() => JsonConvert.SerializeObject(this).GetHashCode();
    }
}
