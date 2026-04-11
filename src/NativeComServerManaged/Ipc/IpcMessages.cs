using System.Text.Json.Serialization;

namespace PasskeyProviderManaged.Ipc;

/// <summary>
/// JSON message schema for the KeePass passkey IPC protocol.
/// Mirrors src/PasskeyWinNative/IPC/IpcProtocol.cs (server side).
/// Uses System.Text.Json source generation for trim-safe serialization.
/// </summary>
internal sealed class IpcRequest
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    // make_credential fields
    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RpId { get; set; }

    [JsonPropertyName("rpName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RpName { get; set; }

    [JsonPropertyName("userId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserId { get; set; }

    [JsonPropertyName("userName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserName { get; set; }

    [JsonPropertyName("userDisplayName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserDisplayName { get; set; }

    [JsonPropertyName("excludeCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? ExcludeCredentials { get; set; }

    // get_assertion fields
    [JsonPropertyName("clientDataHash")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientDataHash { get; set; }

    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? AllowCredentials { get; set; }
}

internal sealed class IpcResponse
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    // ping
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    // error
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    // make_credential
    [JsonPropertyName("credentialId")]
    public string? CredentialId { get; set; }

    [JsonPropertyName("publicKeyX")]
    public string? PublicKeyX { get; set; }

    [JsonPropertyName("publicKeyY")]
    public string? PublicKeyY { get; set; }

    [JsonPropertyName("authenticatorData")]
    public string? AuthenticatorData { get; set; }

    // get_assertion
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("userDisplayName")]
    public string? UserDisplayName { get; set; }

    // get_credentials
    [JsonPropertyName("credentials")]
    public List<CredentialInfo>? Credentials { get; set; }
}

internal sealed class CredentialInfo
{
    [JsonPropertyName("credentialId")]
    public string? CredentialId { get; set; }

    [JsonPropertyName("rpId")]
    public string? RpId { get; set; }

    [JsonPropertyName("userHandle")]
    public string? UserHandle { get; set; }

    [JsonPropertyName("userName")]
    public string? UserName { get; set; }

    [JsonPropertyName("title")]
    public string? Title { get; set; }
}

/// <summary>
/// Source-generated JSON serializer context.
/// Avoids reflection at runtime for trim/AOT compatibility.
/// </summary>
[JsonSerializable(typeof(IpcRequest))]
[JsonSerializable(typeof(IpcResponse))]
[JsonSerializable(typeof(CredentialInfo))]
[JsonSerializable(typeof(List<CredentialInfo>))]
internal sealed partial class IpcJsonContext : JsonSerializerContext { }
