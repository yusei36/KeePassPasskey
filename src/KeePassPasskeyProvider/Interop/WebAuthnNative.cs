using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Interop;

// ---------------------------------------------------------------------------
// Struct layouts from webauthn.h (Windows SDK 10.0.26100.0).
// All fields use natural alignment (LayoutKind.Sequential, Pack=0) which
// matches MSVC x64 default packing.
// ---------------------------------------------------------------------------

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnExtension
{
    public char* pwszExtensionIdentifier; // LPCWSTR
    public uint cbExtension;
    public void* pvExtension;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnExtensions
{
    public uint cExtensions;
    // implicit 4-byte padding before pointer
    public WebAuthnExtension* pExtensions;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredential
{
    public uint dwVersion;   // WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType; // PCWSTR; use WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = L"public-key"
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialEx
{
    public uint dwVersion;   // WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType;
    public uint dwTransports;
    // struct alignment = 8; size rounds up to 32
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialList
{
    public uint cCredentials;
    // implicit 4-byte padding before pointer
    public WebAuthnCredentialEx** ppCredentials; // array of pointers
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameter
{
    public uint dwVersion;
    public char* pwszCredentialType;
    public int lAlg;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCoseCredentialParameters
{
    public uint cCredentialParameters;
    // implicit 4-byte padding
    public WebAuthnCoseCredentialParameter* pCredentialParameters;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnRpEntityInformation
{
    public uint dwVersion; // WEBAUTHN_RP_ENTITY_INFORMATION_VERSION_1 = 1
    // implicit 4-byte padding before PCWSTR
    public char* pwszId;
    public char* pwszName;
    public char* pwszIcon;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnUserEntityInformation
{
    public uint dwVersion; // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1 = 1
    public uint cbId;
    public byte* pbId;
    public char* pwszName;
    public char* pwszIcon;
    public char* pwszDisplayName;
}

/// <summary>
/// WEBAUTHN_ASSERTION — version 6 (CURRENT_VERSION), 176 bytes on x64.
/// We declare all fields through v6 so the embedded struct layout in
/// WebAuthnCtapCborGetAssertionResponse is correct.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAssertion
{
    // Version 1:
    public uint dwVersion;           // set to WEBAUTHN_ASSERTION_CURRENT_VERSION = 6
    public uint cbAuthenticatorData;
    public byte* pbAuthenticatorData;
    public uint cbSignature;
    // implicit 4-byte padding
    public byte* pbSignature;
    public WebAuthnCredential Credential;
    public uint cbUserId;
    // implicit 4-byte padding
    public byte* pbUserId;
    // Version 2:
    public WebAuthnExtensions Extensions;
    public uint cbCredLargeBlob;
    // implicit 4-byte padding
    public byte* pbCredLargeBlob;
    public uint dwCredLargeBlobStatus;
    // implicit 4-byte padding
    // Version 3:
    public nint pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT (opaque ptr, we never set it)
    // Version 4:
    public uint dwUsedTransport;
    // implicit 4-byte padding
    // Version 5:
    public uint cbUnsignedExtensionOutputs;
    // implicit 4-byte padding
    public byte* pbUnsignedExtensionOutputs;
    // Version 6:
    public uint cbClientDataJSON;
    // implicit 4-byte padding
    public byte* pbClientDataJSON;
    public uint cbAuthenticationResponseJSON;
    // implicit 4-byte padding
    public byte* pbAuthenticationResponseJSON;
}

/// <summary>
/// WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE — passed to WebAuthNEncodeGetAssertionResponse.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionResponse
{
    public WebAuthnAssertion WebAuthNAssertion;          // 176 bytes
    public WebAuthnUserEntityInformation* pUserInformation;
    public uint dwNumberOfCredentials;
    public int lUserSelected;                            // LONG (BOOL works as int)
    public uint cbLargeBlobKey;
    // implicit 4-byte padding
    public byte* pbLargeBlobKey;
    public uint cbUnsignedExtensionOutputs;
    // implicit 4-byte padding
    public byte* pbUnsignedExtensionOutputs;
}

/// <summary>
/// WEBAUTHN_CREDENTIAL_ATTESTATION — version 8 (CURRENT_VERSION), 192 bytes on x64.
/// All fields must be declared so that WebAuthNEncodeMakeCredentialResponse reads
/// the correct offsets when dwVersion = CURRENT_VERSION.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialAttestation
{
    // Version 1:
    public uint dwVersion;           // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = 8
    // implicit 4-byte padding
    public char* pwszFormatType;     // PCWSTR; set to L"none"
    public uint cbAuthenticatorData;
    // implicit 4-byte padding
    public byte* pbAuthenticatorData;
    public uint cbAttestation;
    // implicit 4-byte padding
    public byte* pbAttestation;      // null for "none" format
    public uint dwAttestationDecodeType;
    // implicit 4-byte padding
    public nint pvAttestationDecode; // null
    public uint cbAttestationObject;
    // implicit 4-byte padding
    public byte* pbAttestationObject; // null (encoder builds this)
    public uint cbCredentialId;
    // implicit 4-byte padding
    public byte* pbCredentialId;     // null (encoder builds this)
    // Version 2:
    public WebAuthnExtensions Extensions; // 16 bytes
    // Version 3:
    public uint dwUsedTransport;
    // Version 4:
    public int bEpAtt;
    public int bLargeBlobSupported;
    public int bResidentKey;
    // Version 5:
    public int bPrfEnabled;
    // Version 6: (cbUnsignedExtensionOutputs @ 132, pbUnsignedExtensionOutputs @ 136)
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs; // 136 is 8-byte aligned, no pad before this
    // Version 7: (pHmacSecret @ 144)
    public nint pHmacSecret;
    public int bThirdPartyPayment;
    // Version 8: (dwTransports @ 156, cbClientDataJSON @ 160, pbClientDataJSON @ 168)
    public uint dwTransports;
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;   // 168 is 8-byte aligned, no pad
    public uint cbRegistrationResponseJSON;
    // implicit 4-byte padding
    public byte* pbRegistrationResponseJSON;
}

/// <summary>
/// Partial declaration of WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST.
/// We only declare through the CredentialList field, which is all we read.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborMakeCredentialRequest
{
    public uint dwVersion;
    public uint cbRpId;
    public byte* pbRpId;
    public uint cbClientDataHash;
    // implicit 4-byte padding
    public byte* pbClientDataHash;
    public WebAuthnRpEntityInformation* pRpInformation;
    public WebAuthnUserEntityInformation* pUserInformation;
    public WebAuthnCoseCredentialParameters WebAuthNCredentialParameters;
    public WebAuthnCredentialList CredentialList;
    // remaining fields (cbCborExtensionsMap, etc.) omitted — not accessed
}

/// <summary>
/// Partial declaration of WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST.
/// We only declare through the CredentialList field.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionRequest
{
    public uint dwVersion;
    // implicit 4-byte padding before PCWSTR
    public char* pwszRpId;
    public uint cbRpId;
    // implicit 4-byte padding
    public byte* pbRpId;
    public uint cbClientDataHash;
    // implicit 4-byte padding
    public byte* pbClientDataHash;
    public WebAuthnCredentialList CredentialList;
    // remaining fields omitted — not accessed
}

/// <summary>
/// Version and type constants from webauthn.h.
/// </summary>
internal static class WebAuthnConstants
{
    public const uint AttestationCurrentVersion = 8;  // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION
    public const uint AssertionCurrentVersion   = 6;  // WEBAUTHN_ASSERTION_CURRENT_VERSION
    public const uint CredentialVersion         = 1;  // WEBAUTHN_CREDENTIAL_CURRENT_VERSION
    public const uint UserEntityVersion         = 1;  // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1
    public const string CredentialTypePublicKey = "public-key"; // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
}

/// <summary>
/// P/Invoke for webauthn.h encode/decode functions.
/// All calls are resolved at runtime from webauthn.dll.
/// </summary>
internal static unsafe class WebAuthnApi
{
    private const string WebAuthnDll = "webauthn.dll";

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNDecodeMakeCredentialRequest(
        uint cbEncoded,
        byte* pbEncoded,
        WebAuthnCtapCborMakeCredentialRequest** ppRequest);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreeDecodedMakeCredentialRequest(
        WebAuthnCtapCborMakeCredentialRequest* pRequest);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNDecodeGetAssertionRequest(
        uint cbEncoded,
        byte* pbEncoded,
        WebAuthnCtapCborGetAssertionRequest** ppRequest);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreeDecodedGetAssertionRequest(
        WebAuthnCtapCborGetAssertionRequest* pRequest);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNEncodeMakeCredentialResponse(
        WebAuthnCredentialAttestation* pAttestation,
        uint* pcbResp,
        byte** ppbResp);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNEncodeGetAssertionResponse(
        WebAuthnCtapCborGetAssertionResponse* pResponse,
        uint* pcbResp,
        byte** ppbResp);
}
