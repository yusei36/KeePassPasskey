using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

namespace KeePassPasskey.Shared.Ipc
{
    // All messages use length-prefixed framing: [4-byte LE uint32 length][UTF-8 JSON]

    [JsonConverter(typeof(PipeRequestConverter))]
    public abstract class PipeRequestBase
    {
        [JsonProperty("type")]
        public abstract string Type { get; }
    }

    public sealed class PingRequest : PipeRequestBase
    {
        public override string Type => "ping";

        [JsonProperty("version")]
        public string Version { get; set; } = PipeConstants.Version;
    }

    public sealed class GetCredentialsRequest : PipeRequestBase
    {
        public override string Type => "get_credentials";

        [JsonProperty("rpId", NullValueHandling = NullValueHandling.Ignore)]
        public string RpId { get; set; }

        [JsonProperty("allowCredentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> AllowCredentials { get; set; }
    }

    public sealed class MakeCredentialRequest : PipeRequestBase
    {
        public override string Type => "make_credential";

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
    }

    public sealed class GetAssertionRequest : PipeRequestBase
    {
        public override string Type => "get_assertion";

        [JsonProperty("rpId")]
        public string RpId { get; set; }

        [JsonProperty("clientDataHash")]
        public string ClientDataHash { get; set; }

        [JsonProperty("allowCredentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> AllowCredentials { get; set; }
    }

    public sealed class CancelRequest : PipeRequestBase
    {
        public override string Type => "cancel";
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

    [JsonConverter(typeof(PipeResponseConverter))]
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
        public PingResponse() { Type = "ping"; }

        [JsonProperty("status", NullValueHandling = NullValueHandling.Ignore)]
        public PingStatus? Status { get; set; }

        [JsonProperty("version")]
        public string Version { get; set; } = PipeConstants.Version;
    }

    public sealed class GetCredentialsResponse : PipeResponseBase
    {
        public GetCredentialsResponse() { Type = "get_credentials"; }

        [JsonProperty("credentials")]
        public List<CredentialInfo> Credentials { get; set; }
    }

    public sealed class MakeCredentialResponse : PipeResponseBase
    {
        public MakeCredentialResponse() { Type = "make_credential"; }

        [JsonProperty("credentialId")]
        public string CredentialId { get; set; }

        [JsonProperty("coseKey", NullValueHandling = NullValueHandling.Ignore)]
        public string CoseKey { get; set; }
    }

    public sealed class GetAssertionResponse : PipeResponseBase
    {
        public GetAssertionResponse() { Type = "get_assertion"; }

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
        public CancelResponse() { Type = "cancel"; }

        [JsonProperty("status")]
        public string Status { get; set; }
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
                "ping"             => new PingRequest(),
                "get_credentials"  => new GetCredentialsRequest(),
                "make_credential"  => new MakeCredentialRequest(),
                "get_assertion"    => new GetAssertionRequest(),
                "cancel"           => new CancelRequest(),
                _ => throw new JsonSerializationException($"Unknown request type: {type}")
            };
            serializer.Populate(jobj.CreateReader(), result);
            return result;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            => throw new NotSupportedException();
    }

    internal sealed class PipeResponseConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType) => objectType == typeof(PipeResponseBase);
        public override bool CanWrite => false;

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var jobj = JObject.Load(reader);
            string type = (string)jobj["type"];
            PipeResponseBase result = type switch
            {
                "ping"             => new PingResponse(),
                "get_credentials"  => new GetCredentialsResponse(),
                "make_credential"  => new MakeCredentialResponse(),
                "get_assertion"    => new GetAssertionResponse(),
                "cancel"           => new CancelResponse(),
                _                  => new PipeResponseBase()
            };
            serializer.Populate(jobj.CreateReader(), result);
            return result;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            => throw new NotSupportedException();
    }
}
