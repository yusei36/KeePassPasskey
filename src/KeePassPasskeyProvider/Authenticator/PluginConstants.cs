namespace KeePassPasskeyProvider.Authenticator;

internal static class PluginConstants
{
    /// <summary>KeePassPasskey Provider COM server CLSID.</summary>
    public static readonly Guid KeePassPasskeyProviderClsid = new("4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e");

    /// <summary>KeePassPasskey Provider AAGUID.</summary>
    public static readonly Guid KeePassPasskeyProviderAaguid = new("9addb28c-b46f-4402-808f-019651441ff3");

    /// <summary>AAGUID as 16 bytes in RFC 4122 big-endian order, for use in authenticatorData and CBOR.</summary>
    public static readonly byte[] KeePassPasskeyProviderAaguidBytes = AaguidToRfc4122Bytes(KeePassPasskeyProviderAaguid);

    private static byte[] AaguidToRfc4122Bytes(Guid guid)
    {
        var bytes = new byte[16];
        guid.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    public const string PluginName      = "KeePassPasskey "; // trailing space is to work around Windows quirk where in some contexts the name is not properly displayed
    public const string PluginRpId      = "keepasspasskey.github.io";
    public const string PluginRegPath   = @"Software\KeePassPasskeyProvider";
    public const string RegKeySigningKey = "OpSigningPublicKey";
}
