namespace PasskeyProviderManaged.Util;

/// <summary>
/// Base64url encode/decode helpers (RFC 4648 §5, no padding).
/// Used for credential IDs and user handles, which are stored as base64url
/// in both the KeePass plugin's IPC protocol and Windows's credential cache.
/// </summary>
internal static class Base64Url
{
    /// <summary>Encodes bytes as base64url (no padding).</summary>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;
        string b64 = Convert.ToBase64String(data);
        // Replace standard base64 chars that differ in base64url
        return b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>Decodes a base64url string (with or without padding).</summary>
    public static byte[] Decode(string b64url)
    {
        if (string.IsNullOrEmpty(b64url)) return Array.Empty<byte>();
        // Restore standard base64 chars
        string b64 = b64url.Replace('-', '+').Replace('_', '/');
        // Re-add padding
        int pad = b64.Length % 4;
        if (pad == 2) b64 += "==";
        else if (pad == 3) b64 += "=";
        return Convert.FromBase64String(b64);
    }
}
