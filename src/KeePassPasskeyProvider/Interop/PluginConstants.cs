namespace KeePassPasskeyProvider.Interop;

/// <summary>
/// IID and CLSID constants for the KeePass passkey provider.
/// CLSID: 4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e (COM server identity).
/// AAGUID: 9addb28c-b46f-4402-808f-019651441ff3
/// IPluginAuthenticator IID from pluginauthenticator.h: d26bcf6f-b54c-43ff-9f06-d5bf148625f7.
/// </summary>
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

    /// <summary>IPluginAuthenticator IID (from pluginauthenticator.h MIDL_INTERFACE).</summary>
    public static readonly Guid IID_IPluginAuthenticator = new("d26bcf6f-b54c-43ff-9f06-d5bf148625f7");

    /// <summary>IClassFactory IID (standard COM).</summary>
    public static readonly Guid IID_IClassFactory = new("00000001-0000-0000-C000-000000000046");

    /// <summary>IUnknown IID (standard COM).</summary>
    public static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");

    public const string PluginName = "KeePassPasskey";
    public const string PluginRpId = "keepass.info";
    public const string PluginRegPath = @"Software\KeePassPasskeyProvider";
    public const string RegKeySigningKey = "OpSigningPublicKey";
    public const string CredentialTypePublicKey = "public-key";

    // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = 8
    public const uint AttestationCurrentVersion = 8;
    // WEBAUTHN_ASSERTION_CURRENT_VERSION = 6
    public const uint AssertionCurrentVersion = 6;
    // WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1
    public const uint CredentialVersion = 1;
    // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1 = 1
    public const uint UserEntityVersion = 1;

    // HRESULT constants
    public const int S_OK = 0;
    public const int E_INVALIDARG = unchecked((int)0x80070057);
    public const int E_OUTOFMEMORY = unchecked((int)0x8007000E);
    public const int E_FAIL = unchecked((int)0x80004005);
    public const int E_NOINTERFACE = unchecked((int)0x80004002);
    public const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);
    public const int NTE_BAD_SIGNATURE = unchecked((int)0x80090006);
    public const int NTE_NOT_FOUND = unchecked((int)0x80090011);
    public const int NTE_USER_CANCELLED = unchecked((int)0x80090036);
    public static int HRESULT_FROM_WIN32_ERROR_LOCK_VIOLATION => unchecked((int)0x80070021);
    public static int HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS => unchecked((int)0x800700B7);
}
