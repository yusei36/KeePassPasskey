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

