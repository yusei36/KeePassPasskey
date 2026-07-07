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
        public UserVerificationMode RegistrationVerification { get; set; } = UserVerificationMode.Both;

        [JsonProperty("signInVerification")]
        public UserVerificationMode SignInVerification { get; set; } = UserVerificationMode.Both;

        [JsonProperty("showErrorNotifications")]
        public bool ShowErrorNotifications { get; set; } = true;

        [JsonProperty("addPasskeyTag")]
        public bool AddPasskeyTag { get; set; } = true;
        
        [JsonProperty("saveToExistingEntry")]
        public bool SaveToExistingEntry { get; set; } = true;

        [JsonProperty("entryTitleTemplate")]
        public string EntryTitleTemplate { get; set; } = "{RP_NAME} (Passkey)";

        [JsonProperty("resolveTitlePlaceholders")]
        public bool ResolveTitlePlaceholders { get; set; } = true;

        [JsonProperty("newEntryGroupMode")]
        [JsonConverter(typeof(StringEnumConverter))]
        public PasskeyEntryGroupMode NewEntryGroupMode { get; set; } = PasskeyEntryGroupMode.PasskeysGroup;

        [JsonProperty("notificationVerificationTimeoutMilliseconds")]
        public int NotificationVerificationTimeoutMilliseconds { get; set; } = 30_000;

        [JsonProperty("logLevel")]
        [JsonConverter(typeof(StringEnumConverter))]
#if DEBUG
        public LogLevel LogLevel { get; set; } = LogLevel.Debug;
#else
        public LogLevel LogLevel { get; set; } = LogLevel.Info;
#endif

        // Whether passkey metadata is synced to the Windows credential cache so passkeys appear in
        // the Windows sign-in UI. Population is driven by the KeePass plugin on database events; this
        // is the on/off gate. Disabling it clears the cache.
        [JsonProperty("syncCredentialsToWindows")]
        public bool IsCredentialSyncEnabled { get; set; } = true;

        [JsonProperty("statusRefreshIntervalMilliseconds")]
        public int StatusRefreshIntervalMilliseconds { get; set; } = 30_000;

        // JSON-based comparison keeps Equals auto-maintaining: new fields are included
        // automatically without needing to update this method. If performance ever becomes
        // a concern, replace with explicit field-by-field comparison.
#if NET5_0_OR_GREATER
        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
#endif
        public override bool Equals(object obj)
        {
            if (obj is not KeePassPasskeySettings other) return false;
            return JsonConvert.SerializeObject(this) == JsonConvert.SerializeObject(other);
        }

#if NET5_0_OR_GREATER
        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
#endif
        public override int GetHashCode() => JsonConvert.SerializeObject(this).GetHashCode();

#if NET5_0_OR_GREATER
        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
#endif
        public KeePassPasskeySettings Clone() =>
            JsonConvert.DeserializeObject<KeePassPasskeySettings>(JsonConvert.SerializeObject(this))!;
    }
}
