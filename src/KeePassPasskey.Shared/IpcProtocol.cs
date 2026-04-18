using System.Collections.Generic;
using Newtonsoft.Json;

namespace KeePassPasskey.Shared
{
    // All messages use length-prefixed framing: [4-byte LE uint32 length][UTF-8 JSON]

    public sealed class IpcRequest
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        // make_credential fields
        [JsonProperty("rpId")]
        public string RpId { get; set; }

        [JsonProperty("rpName")]
        public string RpName { get; set; }

        [JsonProperty("userId")]
        public string UserId { get; set; }

        [JsonProperty("userName")]
        public string UserName { get; set; }

        [JsonProperty("userDisplayName")]
        public string UserDisplayName { get; set; }

        [JsonProperty("excludeCredentials")]
        public List<string> ExcludeCredentials { get; set; }

        // get_assertion fields
        [JsonProperty("clientDataHash")]
        public string ClientDataHash { get; set; }

        [JsonProperty("allowCredentials")]
        public List<string> AllowCredentials { get; set; }
    }

    public sealed class IpcResponse
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        // error response
        [JsonProperty("code", NullValueHandling = NullValueHandling.Ignore)]
        public string Code { get; set; }

        [JsonProperty("message", NullValueHandling = NullValueHandling.Ignore)]
        public string Message { get; set; }

        // ping response
        [JsonProperty("status", NullValueHandling = NullValueHandling.Ignore)]
        public string Status { get; set; }

        // make_credential response
        [JsonProperty("credentialId", NullValueHandling = NullValueHandling.Ignore)]
        public string CredentialId { get; set; }

        [JsonProperty("publicKeyX", NullValueHandling = NullValueHandling.Ignore)]
        public string PublicKeyX { get; set; }

        [JsonProperty("publicKeyY", NullValueHandling = NullValueHandling.Ignore)]
        public string PublicKeyY { get; set; }

        [JsonProperty("authenticatorData", NullValueHandling = NullValueHandling.Ignore)]
        public string AuthenticatorData { get; set; }

        // get_assertion response
        [JsonProperty("signature", NullValueHandling = NullValueHandling.Ignore)]
        public string Signature { get; set; }

        [JsonProperty("userHandle", NullValueHandling = NullValueHandling.Ignore)]
        public string UserHandle { get; set; }

        [JsonProperty("userName", NullValueHandling = NullValueHandling.Ignore)]
        public string UserName { get; set; }

        [JsonProperty("userDisplayName", NullValueHandling = NullValueHandling.Ignore)]
        public string UserDisplayName { get; set; }

        // get_credentials response
        [JsonProperty("credentials", NullValueHandling = NullValueHandling.Ignore)]
        public List<CredentialInfo> Credentials { get; set; }
    }

    public sealed class IpcErrorResponse
    {
        [JsonProperty("type")]
        public string Type => "error";

        [JsonProperty("code")]
        public string Code { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }
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
}
