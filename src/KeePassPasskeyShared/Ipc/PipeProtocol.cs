// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace KeePassPasskeyShared.Ipc
{
    // All messages use length-prefixed framing: [4-byte LE uint32 length][UTF-8 JSON]

    public static class PipeMessageTypes
    {
        public const string Ping           = "ping";
        public const string GetCredentials = "get_credentials";
        public const string GetDatabases   = "get_databases";
        public const string MakeCredential = "make_credential";
        public const string GetAssertion   = "get_assertion";
        public const string Cancel         = "cancel";
        public const string GetSettings    = "get_settings";
        public const string SaveSettings   = "save_settings";
    }

    [JsonConverter(typeof(PipeRequestConverter))]
    public abstract class PipeRequestBase
    {
        [JsonProperty("type")]
        public abstract string Type { get; }
    }

    public sealed class PingRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.Ping;

        [JsonProperty("version")]
        public string Version { get; set; } = PipeConstants.Version;
    }

    public sealed class GetCredentialsRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.GetCredentials;

        [JsonProperty("rpId", NullValueHandling = NullValueHandling.Ignore)]
        public string RpId { get; set; }

        [JsonProperty("allowCredentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> AllowCredentials { get; set; }
    }

    public sealed class GetDatabasesRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.GetDatabases;
    }

    public sealed class MakeCredentialRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.MakeCredential;

        [JsonProperty("rpId")]
        public string RpId { get; set; }

        [JsonProperty("rpName", NullValueHandling = NullValueHandling.Ignore)]
        public string RpName { get; set; }

        [JsonProperty("userId")]
        public string UserId { get; set; }

        [JsonProperty("userName", NullValueHandling = NullValueHandling.Ignore)]
        public string UserName { get; set; }

        [JsonProperty("userDisplayName", NullValueHandling = NullValueHandling.Ignore)]
        public string UserDisplayName { get; set; }

        [JsonProperty("excludeCredentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> ExcludeCredentials { get; set; }

        [JsonProperty("pubKeyCredParams", NullValueHandling = NullValueHandling.Ignore)]
        public List<int> PubKeyCredParams { get; set; }

        [JsonProperty("targetDatabase", NullValueHandling = NullValueHandling.Ignore)]
        public DatabaseInfo TargetDatabase { get; set; }
    }

    public sealed class GetAssertionRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.GetAssertion;

        [JsonProperty("rpId")]
        public string RpId { get; set; }

        [JsonProperty("clientDataHash")]
        public string ClientDataHash { get; set; }

        [JsonProperty("allowCredentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> AllowCredentials { get; set; }

        // TEMP PRF PROBE (remove): cleartext hmac-secret output (base64url, 32 or 64 bytes) the
        // plugin should embed in the signed authData extensions. See docs/prf-implementation-plan.md.
        [JsonProperty("hmacSecretOutput", NullValueHandling = NullValueHandling.Ignore)]
        public string HmacSecretOutput { get; set; }
    }

    public sealed class CancelRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.Cancel;
    }

    public sealed class GetSettingsRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.GetSettings;
    }

    public sealed class SaveSettingsRequest : PipeRequestBase
    {
        public override string Type => PipeMessageTypes.SaveSettings;

        [JsonProperty("settings")]
        public KeePassPasskeySettings Settings { get; set; }
    }

    [JsonConverter(typeof(StringEnumConverter), typeof(SnakeCaseNamingStrategy))]
    public enum PingStatus
    {
        NotConnected,
        Ready,
        NoDatabase,
        IncompatibleVersion
    }

    [JsonConverter(typeof(StringEnumConverter), typeof(SnakeCaseNamingStrategy))]
    public enum PipeErrorCode
    {
        DbLocked,
        Duplicate,
        NotFound,
        InternalError,
        UnsupportedAlgorithm,
    }

    public class PipeResponseBase
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("errorCode", NullValueHandling = NullValueHandling.Ignore)]
        public PipeErrorCode? ErrorCode { get; set; }

        [JsonProperty("errorMessage", NullValueHandling = NullValueHandling.Ignore)]
        public string ErrorMessage { get; set; }
    }

    public sealed class PingResponse : PipeResponseBase
    {
        public PingResponse() { Type = PipeMessageTypes.Ping; }

        [JsonProperty("status", NullValueHandling = NullValueHandling.Ignore)]
        public PingStatus? Status { get; set; }

        [JsonProperty("version")]
        public string Version { get; set; } = PipeConstants.Version;
    }

    public sealed class GetCredentialsResponse : PipeResponseBase
    {
        public GetCredentialsResponse() { Type = PipeMessageTypes.GetCredentials; }

        [JsonProperty("credentials")]
        public List<CredentialInfo> Credentials { get; set; }
    }

    public sealed class GetDatabasesResponse : PipeResponseBase
    {
        public GetDatabasesResponse() { Type = PipeMessageTypes.GetDatabases; }

        [JsonProperty("databases")]
        public List<DatabaseInfo> Databases { get; set; }
    }

    public sealed class MakeCredentialResponse : PipeResponseBase
    {
        public MakeCredentialResponse() { Type = PipeMessageTypes.MakeCredential; }

        [JsonProperty("credentialId")]
        public string CredentialId { get; set; }

        [JsonProperty("coseKey", NullValueHandling = NullValueHandling.Ignore)]
        public string CoseKey { get; set; }
    }

    public sealed class GetAssertionResponse : PipeResponseBase
    {
        public GetAssertionResponse() { Type = PipeMessageTypes.GetAssertion; }

        [JsonProperty("credentialId")]
        public string CredentialId { get; set; }

        [JsonProperty("authenticatorData")]
        public string AuthenticatorData { get; set; }

        [JsonProperty("signature")]
        public string Signature { get; set; }

        [JsonProperty("userHandle")]
        public string UserHandle { get; set; }

        [JsonProperty("userName")]
        public string UserName { get; set; }

        [JsonProperty("userDisplayName")]
        public string UserDisplayName { get; set; }
    }

    public sealed class CancelResponse : PipeResponseBase
    {
        public CancelResponse() { Type = PipeMessageTypes.Cancel; }

        [JsonProperty("status")]
        public string Status { get; set; }
    }

    public sealed class GetSettingsResponse : PipeResponseBase
    {
        public GetSettingsResponse() { Type = PipeMessageTypes.GetSettings; }

        [JsonProperty("settings")]
        public KeePassPasskeySettings Settings { get; set; }
    }

    public sealed class SaveSettingsResponse : PipeResponseBase
    {
        public SaveSettingsResponse() { Type = PipeMessageTypes.SaveSettings; }
    }

    public sealed class CredentialInfo
    {
        [JsonProperty("credentialId")]
        public string CredentialId { get; set; }

        [JsonProperty("rpId")]
        public string RpId { get; set; }

        [JsonProperty("userHandle")]
        public string UserHandle { get; set; }

        [JsonProperty("userName")]
        public string UserName { get; set; }

        [JsonProperty("title")]
        public string Title { get; set; }
    }

    public sealed class DatabaseInfo
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }
    }


    internal sealed class PipeRequestConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType) => objectType == typeof(PipeRequestBase);
        public override bool CanWrite => false;

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var jobj = JObject.Load(reader);
            string type = (string)jobj["type"];
            PipeRequestBase result = type switch
            {
                PipeMessageTypes.Ping           => new PingRequest(),
                PipeMessageTypes.GetCredentials => new GetCredentialsRequest(),
                PipeMessageTypes.GetDatabases   => new GetDatabasesRequest(),
                PipeMessageTypes.MakeCredential => new MakeCredentialRequest(),
                PipeMessageTypes.GetAssertion   => new GetAssertionRequest(),
                PipeMessageTypes.Cancel         => new CancelRequest(),
                PipeMessageTypes.GetSettings    => new GetSettingsRequest(),
                PipeMessageTypes.SaveSettings   => new SaveSettingsRequest(),
                _ => throw new JsonSerializationException($"Unknown request type: {type}")
            };
            serializer.Populate(jobj.CreateReader(), result);
            return result;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            => throw new NotSupportedException();
    }

}
