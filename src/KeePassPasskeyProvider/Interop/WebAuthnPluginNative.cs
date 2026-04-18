using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Interop;

// ---------------------------------------------------------------------------
// Struct layouts from webauthnplugin.h + pluginauthenticator.h
// (Windows SDK 10.0.26100.0).  Not in the shipped Win32 winmd.
// ---------------------------------------------------------------------------

internal enum PluginLockStatus : int
{
    PluginLocked = 0,
    PluginUnlocked = 1,
}

internal enum AuthenticatorState : int
{
    AuthenticatorState_Disabled = 0,
    AuthenticatorState_Enabled = 1,
}

internal enum WebAuthnPluginRequestType : uint
{
    Ctap2Cbor = 1,
}

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_REQUEST — passed in by the platform (read only).
/// Layout (x64): HWND(8) + GUID(16) + DWORD(4) + [4 pad] + ptr(8) + DWORD(4) + DWORD(4) + ptr(8) = 56 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationRequest
{
    public nint hWnd;                              // HWND (8 bytes x64)
    public Guid transactionId;                     // 16 bytes
    public uint cbRequestSignature;                // 4 bytes
    // implicit 4-byte padding before pointer
    public byte* pbRequestSignature;               // 8 bytes
    public WebAuthnPluginRequestType requestType;  // 4 bytes (enum = DWORD)
    public uint cbEncodedRequest;                  // 4 bytes  (no pad — two DWORDs in a row)
    public byte* pbEncodedRequest;                 // 8 bytes  (48 is 8-byte aligned ✓)
}

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_RESPONSE — written by the authenticator.
/// Layout: DWORD(4) + [4 pad] + ptr(8) = 16 bytes.
/// pbEncodedResponse is allocated by WebAuthNEncode*, owned and freed by the platform.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationResponse
{
    public uint cbEncodedResponse;
    // implicit 4-byte padding
    public byte* pbEncodedResponse;
}

/// <summary>
/// WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST — passed in by the platform.
/// Layout: GUID(16) + DWORD(4) + [4 pad] + ptr(8) = 32 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCancelOperationRequest
{
    public Guid transactionId;
    public uint cbRequestSignature;
    // implicit 4-byte padding
    public byte* pbRequestSignature;
}

/// <summary>
/// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS — built by us, passed to WebAuthNPluginAddAuthenticator.
/// rclsid is REFCLSID = const CLSID* (8-byte pointer on x64).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions
{
    public char* pwszAuthenticatorName;  // LPCWSTR (8)
    public Guid* rclsid;                 // REFCLSID = pointer to CLSID (8)
    public char* pwszPluginRpId;         // LPCWSTR (8)
    public char* pwszLightThemeLogoSvg;  // LPCWSTR (8, null)
    public char* pwszDarkThemeLogoSvg;   // LPCWSTR (8, null)
    public uint cbAuthenticatorInfo;     // DWORD (4)
    // implicit 4-byte padding
    public byte* pbAuthenticatorInfo;    // const BYTE* (8)
    public uint cSupportedRpIds;         // DWORD (4, 0 = all RPs supported)
    // implicit 4-byte padding
    public char** ppwszSupportedRpIds;   // const LPCWSTR* (8, null)
}

/// <summary>
/// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE — received from WebAuthNPluginAddAuthenticator.
/// Layout: DWORD(4) + [4 pad] + ptr(8) = 16 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorResponse
{
    public uint cbOpSignPubKey;
    // implicit 4-byte padding
    public byte* pbOpSignPubKey;
}

/// <summary>
/// WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS — one entry in the Windows autofill cache.
/// Layout: 64 bytes (4 DWORD/pointer pairs + 4 pointers).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCredentialDetails
{
    public uint cbCredentialId;
    // implicit 4-byte padding
    public byte* pbCredentialId;
    public char* pwszRpId;               // LPCWSTR
    public char* pwszRpName;             // LPCWSTR
    public uint cbUserId;
    // implicit 4-byte padding
    public byte* pbUserId;
    public char* pwszUserName;           // LPCWSTR
    public char* pwszUserDisplayName;    // LPCWSTR
}

/// <summary>
/// P/Invoke for webauthnplugin.h functions.
/// All resolved at runtime from webauthn.dll.
/// </summary>
internal static unsafe class WebAuthnPluginApi
{
    private const string WebAuthnDll = "webauthn.dll";

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginAddAuthenticator(
        WebAuthnPluginAddAuthenticatorOptions* pOptions,
        WebAuthnPluginAddAuthenticatorResponse** ppResponse);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNPluginFreeAddAuthenticatorResponse(
        WebAuthnPluginAddAuthenticatorResponse* pResponse);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginRemoveAuthenticator(in Guid rclsid);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginGetAuthenticatorState(
        in Guid rclsid,
        AuthenticatorState* pState);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginAuthenticatorAddCredentials(
        in Guid rclsid,
        uint cCredentialDetails,
        WebAuthnPluginCredentialDetails* pCredentialDetails);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginAuthenticatorRemoveCredentials(
        in Guid rclsid,
        uint cCredentialDetails,
        WebAuthnPluginCredentialDetails* pCredentialDetails);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNPluginAuthenticatorGetAllCredentials(
        in Guid rclsid,
        uint* pcCredentialDetails,
        WebAuthnPluginCredentialDetails** ppCredentialDetailsArray);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(
        uint cCredentialDetails,
        WebAuthnPluginCredentialDetails* pCredentialDetailsArray);
}

/// <summary>
/// IID and CLSID constants for the KeePass passkey provider.
/// CLSID: 4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e (COM server identity).
/// AAGUID: fdb141b2-5d84-443e-8a35-4698c205a502 (KeePassXC-compatible, embedded in credentials).
/// IPluginAuthenticator IID from pluginauthenticator.h: d26bcf6f-b54c-43ff-9f06-d5bf148625f7.
/// </summary>
internal static class PluginConstants
{
    /// <summary>KeePassPasskey Provider COM server CLSID.</summary>
    public static readonly Guid KeePassPasskeyProviderClsid = new("4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e");

    /// <summary>KeePassXC-compatible AAGUID.</summary>
    public static readonly Guid KeePassPasskeyProviderAaguid = new("fdb141b2-5d84-443e-8a35-4698c205a502");

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
