// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Authenticator.Native;

// =============================================================================
// Complete managed transcription of webauthn.h (Windows SDK, WEBAUTHN_API_VERSION_9):
// the WebAuthN data structures, constants, and client API entry points.
//
// The CTAP-CBOR structures and encode/decode entry points from webauthnplugin.h
// live in WebAuthnPluginNative.cs; the IPluginAuthenticator contract from
// pluginauthenticator.h lives in PluginAuthenticatorNative.cs.
//
// Source: https://github.com/microsoft/webauthn (webauthn.h).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// ABI notes (x64):
//   * All structs use LayoutKind.Sequential with default packing (Pack = 0),
//     which reproduces MSVC's natural alignment for these blittable types. The
//     CLR inserts the same implicit padding the C compiler does, so no explicit
//     padding fields are required.
//   * DWORD -> uint, LONG/BOOL -> int, WORD -> ushort, PBYTE/byte* -> byte*,
//     PCWSTR/LPCWSTR -> char*, PVOID -> void*, HWND -> nint, GUID -> System.Guid.
//   * BOOL is a 4-byte int; never use managed bool inside these structs.
// =============================================================================

#region Constants

/// <summary>
/// Version, algorithm, transport, and option constants from webauthn.h.
/// </summary>
internal static class WebAuthnConstants
{
    // API versions ----------------------------------------------------------
    public const uint ApiVersion1 = 1;
    public const uint ApiVersion2 = 2;
    public const uint ApiVersion3 = 3;
    public const uint ApiVersion4 = 4;
    public const uint ApiVersion5 = 5;
    public const uint ApiVersion6 = 6;
    public const uint ApiVersion7 = 7;
    public const uint ApiVersion8 = 8;
    public const uint ApiVersion9 = 9;
    public const uint ApiCurrentVersion = ApiVersion9;

    // Structure versions ----------------------------------------------------
    public const uint RpEntityInformationCurrentVersion   = 1; // WEBAUTHN_RP_ENTITY_INFORMATION
    public const uint UserEntityVersion                   = 1; // WEBAUTHN_USER_ENTITY_INFORMATION_VERSION_1 (kept name: used by callers)
    public const uint ClientDataCurrentVersion            = 1;
    public const uint CoseCredentialParameterCurrentVersion = 1;
    public const uint CredentialVersion                   = 1; // WEBAUTHN_CREDENTIAL_CURRENT_VERSION (kept name: used by callers)
    public const uint CredentialExCurrentVersion          = 1;
    public const uint AuthenticatorDetailsOptionsCurrentVersion = 1;
    public const uint AuthenticatorDetailsCurrentVersion  = 1;
    public const uint CredentialDetailsCurrentVersion     = 4;
    public const uint GetCredentialsOptionsCurrentVersion = 1;
    public const uint MakeCredentialOptionsCurrentVersion = 9;
    public const uint GetAssertionOptionsCurrentVersion   = 9;
    public const uint CommonAttestationCurrentVersion     = 1;
    public const uint AttestationCurrentVersion           = 8; // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION (kept name)
    public const uint AssertionCurrentVersion             = 6; // WEBAUTHN_ASSERTION_CURRENT_VERSION (kept name)

    public const uint MaxUserIdLength = 64;

    // Credential type -------------------------------------------------------
    public const string CredentialTypePublicKey = "public-key"; // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY (kept name)

    // Hash algorithm identifiers --------------------------------------------
    public const string HashAlgorithmSha256 = "SHA-256";
    public const string HashAlgorithmSha384 = "SHA-384";
    public const string HashAlgorithmSha512 = "SHA-512";

    // COSE algorithm identifiers --------------------------------------------
    public const int CoseAlgorithmEcdsaP256WithSha256 = -7;
    public const int CoseAlgorithmEcdsaP384WithSha384 = -35;
    public const int CoseAlgorithmEcdsaP521WithSha512 = -36;
    public const int CoseAlgorithmRsassaPkcs1V15WithSha256 = -257;
    public const int CoseAlgorithmRsassaPkcs1V15WithSha384 = -258;
    public const int CoseAlgorithmRsassaPkcs1V15WithSha512 = -259;
    public const int CoseAlgorithmRsaPssWithSha256 = -37;
    public const int CoseAlgorithmRsaPssWithSha384 = -38;
    public const int CoseAlgorithmRsaPssWithSha512 = -39;

    // CTAP transports -------------------------------------------------------
    public const uint CtapTransportUsb        = 0x00000001;
    public const uint CtapTransportNfc        = 0x00000002;
    public const uint CtapTransportBle        = 0x00000004;
    public const uint CtapTransportTest       = 0x00000008;
    public const uint CtapTransportInternal   = 0x00000010;
    public const uint CtapTransportHybrid     = 0x00000020;
    public const uint CtapTransportSmartCard  = 0x00000040;
    public const uint CtapTransportFlagsMask  = 0x0000007F;

    // Authenticator attachment ----------------------------------------------
    public const uint AuthenticatorAttachmentAny                = 0;
    public const uint AuthenticatorAttachmentPlatform           = 1;
    public const uint AuthenticatorAttachmentCrossPlatform      = 2;
    public const uint AuthenticatorAttachmentCrossPlatformU2fV2 = 3;

    // User verification requirement -----------------------------------------
    public const uint UserVerificationRequirementAny         = 0;
    public const uint UserVerificationRequirementRequired    = 1;
    public const uint UserVerificationRequirementPreferred   = 2;
    public const uint UserVerificationRequirementDiscouraged = 3;

    // credProtect user verification -----------------------------------------
    public const uint UserVerificationAny                              = 0;
    public const uint UserVerificationOptional                         = 1;
    public const uint UserVerificationOptionalWithCredentialIdList     = 2;
    public const uint UserVerificationRequired                         = 3;

    // Attestation conveyance preference -------------------------------------
    public const uint AttestationConveyancePreferenceAny      = 0;
    public const uint AttestationConveyancePreferenceNone     = 1;
    public const uint AttestationConveyancePreferenceIndirect = 2;
    public const uint AttestationConveyancePreferenceDirect   = 3;

    // Enterprise attestation ------------------------------------------------
    public const uint EnterpriseAttestationNone             = 0;
    public const uint EnterpriseAttestationVendorFacilitated = 1;
    public const uint EnterpriseAttestationPlatformManaged  = 2;

    // Large blob support ----------------------------------------------------
    public const uint LargeBlobSupportNone      = 0;
    public const uint LargeBlobSupportRequired  = 1;
    public const uint LargeBlobSupportPreferred = 2;

    // Large blob operation --------------------------------------------------
    public const uint CredLargeBlobOperationNone   = 0;
    public const uint CredLargeBlobOperationGet    = 1;
    public const uint CredLargeBlobOperationSet    = 2;
    public const uint CredLargeBlobOperationDelete = 3;

    // Large blob status -----------------------------------------------------
    public const uint CredLargeBlobStatusNone                = 0;
    public const uint CredLargeBlobStatusSuccess             = 1;
    public const uint CredLargeBlobStatusNotSupported        = 2;
    public const uint CredLargeBlobStatusInvalidData         = 3;
    public const uint CredLargeBlobStatusInvalidParameter    = 4;
    public const uint CredLargeBlobStatusNotFound            = 5;
    public const uint CredLargeBlobStatusMultipleCredentials = 6;
    public const uint CredLargeBlobStatusLackOfSpace         = 7;
    public const uint CredLargeBlobStatusPlatformError       = 8;
    public const uint CredLargeBlobStatusAuthenticatorError  = 9;

    // Attestation decode type -----------------------------------------------
    public const uint AttestationDecodeNone   = 0;
    public const uint AttestationDecodeCommon = 1;

    // Attestation format types ----------------------------------------------
    public const string AttestationTypePacked = "packed";
    public const string AttestationTypeU2f    = "fido-u2f";
    public const string AttestationTypeTpm    = "tpm";
    public const string AttestationTypeNone   = "none";

    // Credential hints ------------------------------------------------------
    public const string CredentialHintSecurityKey = "security-key";
    public const string CredentialHintClientDevice = "client-device";
    public const string CredentialHintHybrid       = "hybrid";

    // Extension identifiers -------------------------------------------------
    public const string ExtensionsIdentifierHmacSecret  = "hmac-secret";
    public const string ExtensionsIdentifierCredProtect = "credProtect";
    public const string ExtensionsIdentifierCredBlob    = "credBlob";
    public const string ExtensionsIdentifierMinPinLength = "minPinLength";

    // PRF / HMAC-secret -----------------------------------------------------
    public const uint CtapOneHmacSecretLength    = 32;
    public const uint AuthenticatorHmacSecretValuesFlag = 0x00100000;
}

#endregion

#region Core structures

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnRpEntityInformation
{
    public uint dwVersion; // WEBAUTHN_RP_ENTITY_INFORMATION_VERSION_1 = 1
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

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnClientData
{
    public uint dwVersion; // WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;
    public char* pwszHashAlgId; // L"SHA-256" etc.
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
    public WebAuthnCoseCredentialParameter* pCredentialParameters; // array of cCredentialParameters
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredential
{
    public uint dwVersion;   // WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType; // WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = L"public-key"
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentials
{
    public uint cCredentials;
    public WebAuthnCredential* pCredentials; // array of cCredentials
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialEx
{
    public uint dwVersion;   // WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1
    public uint cbId;
    public byte* pbId;
    public char* pwszCredentialType;
    public uint dwTransports;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialList
{
    public uint cCredentials;
    public WebAuthnCredentialEx** ppCredentials; // array of pointers
}

/// <summary>CTAPCBOR_HYBRID_STORAGE_LINKED_DATA (deprecated).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct CtapCborHybridStorageLinkedData
{
    public uint dwVersion;
    public uint cbContactId;
    public byte* pbContactId;
    public uint cbLinkId;
    public byte* pbLinkId;
    public uint cbLinkSecret;
    public byte* pbLinkSecret;
    public uint cbPublicKey;
    public byte* pbPublicKey;
    public char* pwszAuthenticatorName;
    public ushort wEncodedTunnelServerDomain;
}

#endregion

#region Authenticator list / credential details

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetailsOptions
{
    public uint dwVersion;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetails
{
    public uint dwVersion;
    public uint cbAuthenticatorId;
    public byte* pbAuthenticatorId;
    public char* pwszAuthenticatorName;
    public uint cbAuthenticatorLogo;
    public byte* pbAuthenticatorLogo;
    public int bLocked; // BOOL
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorDetailsList
{
    public uint cAuthenticatorDetails;
    public WebAuthnAuthenticatorDetails** ppAuthenticatorDetails;
}

/// <summary>WEBAUTHN_CREDENTIAL_DETAILS (version 4).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialDetails
{
    public uint dwVersion;
    public uint cbCredentialID;
    public byte* pbCredentialID;
    public WebAuthnRpEntityInformation* pRpInformation;
    public WebAuthnUserEntityInformation* pUserInformation;
    public int bRemovable;          // BOOL
    // Version 2:
    public int bBackedUp;           // BOOL
    // Version 3:
    public char* pwszAuthenticatorName;
    public uint cbAuthenticatorLogo;
    public byte* pbAuthenticatorLogo;
    public int bThirdPartyPayment;  // BOOL
    // Version 4:
    public uint dwTransports;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialDetailsList
{
    public uint cCredentialDetails;
    public WebAuthnCredentialDetails** ppCredentialDetails;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnGetCredentialsOptions
{
    public uint dwVersion;
    public char* pwszRpId;            // optional
    public int bBrowserInPrivateMode; // BOOL
}

#endregion

#region PRF / HMAC-secret salt values

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnHmacSecretSalt
{
    public uint cbFirst;
    public byte* pbFirst;
    public uint cbSecond;
    public byte* pbSecond;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredWithHmacSecretSalt
{
    public uint cbCredID;
    public byte* pbCredID;
    public WebAuthnHmacSecretSalt* pHmacSecretSalt;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnHmacSecretSaltValues
{
    public WebAuthnHmacSecretSalt* pGlobalHmacSalt;
    public uint cCredWithHmacSecretSaltList;
    public WebAuthnCredWithHmacSecretSalt* pCredWithHmacSecretSaltList;
}

#endregion

#region Extensions

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredProtectExtensionIn
{
    public uint dwCredProtect; // one of WEBAUTHN_USER_VERIFICATION_*
    public int bRequireCredProtect; // BOOL
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredBlobExtension
{
    public uint cbCredBlob;
    public byte* pbCredBlob;
}

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
    public WebAuthnExtension* pExtensions;
}

#endregion

#region MakeCredential / GetAssertion options

/// <summary>WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (version 9).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorMakeCredentialOptions
{
    // Version 1:
    public uint dwVersion;
    public uint dwTimeoutMilliseconds;
    public WebAuthnCredentials CredentialList;
    public WebAuthnExtensions Extensions;
    public uint dwAuthenticatorAttachment;
    public int bRequireResidentKey; // BOOL
    public uint dwUserVerificationRequirement;
    public uint dwAttestationConveyancePreference;
    public uint dwFlags;
    // Version 2:
    public Guid* pCancellationId;
    // Version 3:
    public WebAuthnCredentialList* pExcludeCredentialList;
    // Version 4:
    public uint dwEnterpriseAttestation;
    public uint dwLargeBlobSupport;
    public int bPreferResidentKey;     // BOOL
    // Version 5:
    public int bBrowserInPrivateMode;  // BOOL
    // Version 6:
    public int bEnablePrf;             // BOOL
    // Version 7:
    public CtapCborHybridStorageLinkedData* pLinkedDevice; // deprecated
    public uint cbJsonExt;
    public byte* pbJsonExt;
    // Version 8:
    public WebAuthnHmacSecretSalt* pPRFGlobalEval;
    public uint cCredentialHints;
    public char** ppwszCredentialHints; // LPCWSTR*
    public int bThirdPartyPayment;      // BOOL
    // Version 9:
    public char* pwszRemoteWebOrigin;
    public uint cbPublicKeyCredentialCreationOptionsJSON;
    public byte* pbPublicKeyCredentialCreationOptionsJSON;
    public uint cbAuthenticatorId;
    public byte* pbAuthenticatorId;
}

/// <summary>WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (version 9).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAuthenticatorGetAssertionOptions
{
    // Version 1:
    public uint dwVersion;
    public uint dwTimeoutMilliseconds;
    public WebAuthnCredentials CredentialList;
    public WebAuthnExtensions Extensions;
    public uint dwAuthenticatorAttachment;
    public uint dwUserVerificationRequirement;
    public uint dwFlags;
    // Version 2:
    public char* pwszU2fAppId;
    public int* pbU2fAppId; // BOOL*
    // Version 3:
    public Guid* pCancellationId;
    // Version 4:
    public WebAuthnCredentialList* pAllowCredentialList;
    // Version 5:
    public uint dwCredLargeBlobOperation;
    public uint cbCredLargeBlob;
    public byte* pbCredLargeBlob;
    // Version 6:
    public WebAuthnHmacSecretSaltValues* pHmacSecretSaltValues;
    public int bBrowserInPrivateMode; // BOOL
    // Version 7:
    public CtapCborHybridStorageLinkedData* pLinkedDevice; // deprecated
    public int bAutoFill;             // BOOL
    public uint cbJsonExt;
    public byte* pbJsonExt;
    // Version 8:
    public uint cCredentialHints;
    public char** ppwszCredentialHints; // LPCWSTR*
    // Version 9:
    public char* pwszRemoteWebOrigin;
    public uint cbPublicKeyCredentialRequestOptionsJSON;
    public byte* pbPublicKeyCredentialRequestOptionsJSON;
    public uint cbAuthenticatorId;
    public byte* pbAuthenticatorId;
}

#endregion

#region Attestation / Assertion output

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnX5c
{
    public uint cbData;
    public byte* pbData;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCommonAttestation
{
    public uint dwVersion;
    public char* pwszAlg;
    public int lAlg; // COSE algorithm
    public uint cbSignature;
    public byte* pbSignature;
    public uint cX5c;
    public WebAuthnX5c* pX5c;
    public char* pwszVer; // L"2.0"
    public uint cbCertInfo;
    public byte* pbCertInfo;
    public uint cbPubArea;
    public byte* pbPubArea;
}

/// <summary>
/// WEBAUTHN_CREDENTIAL_ATTESTATION - version 8 (CURRENT_VERSION), 192 bytes on x64.
/// All fields are declared so WebAuthNEncodeMakeCredentialResponse reads the correct
/// offsets when dwVersion = CURRENT_VERSION.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCredentialAttestation
{
    // Version 1:
    public uint dwVersion;           // WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = 8
    public char* pwszFormatType;     // PCWSTR; e.g. L"none"
    public uint cbAuthenticatorData;
    public byte* pbAuthenticatorData;
    public uint cbAttestation;
    public byte* pbAttestation;
    public uint dwAttestationDecodeType;
    public void* pvAttestationDecode; // PWEBAUTHN_COMMON_ATTESTATION when decoded
    public uint cbAttestationObject;
    public byte* pbAttestationObject;
    public uint cbCredentialId;
    public byte* pbCredentialId;
    // Version 2:
    public WebAuthnExtensions Extensions;
    // Version 3:
    public uint dwUsedTransport;
    // Version 4:
    public int bEpAtt;            // BOOL
    public int bLargeBlobSupported; // BOOL
    public int bResidentKey;      // BOOL
    // Version 5:
    public int bPrfEnabled;       // BOOL
    // Version 6:
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs;
    // Version 7:
    public WebAuthnHmacSecretSalt* pHmacSecret;
    public int bThirdPartyPayment; // BOOL
    // Version 8:
    public uint dwTransports;
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;
    public uint cbRegistrationResponseJSON;
    public byte* pbRegistrationResponseJSON;
}

/// <summary>
/// WEBAUTHN_ASSERTION - version 6 (CURRENT_VERSION), 176 bytes on x64.
/// All fields through v6 are declared so the embedded layout inside
/// WebAuthnCtapCborGetAssertionResponse (WebAuthnPluginNative.cs) is correct.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnAssertion
{
    // Version 1:
    public uint dwVersion;           // WEBAUTHN_ASSERTION_CURRENT_VERSION = 6
    public uint cbAuthenticatorData;
    public byte* pbAuthenticatorData;
    public uint cbSignature;
    public byte* pbSignature;
    public WebAuthnCredential Credential;
    public uint cbUserId;
    public byte* pbUserId;
    // Version 2:
    public WebAuthnExtensions Extensions;
    public uint cbCredLargeBlob;
    public byte* pbCredLargeBlob;
    public uint dwCredLargeBlobStatus;
    // Version 3:
    public WebAuthnHmacSecretSalt* pHmacSecret;
    // Version 4:
    public uint dwUsedTransport;
    // Version 5:
    public uint cbUnsignedExtensionOutputs;
    public byte* pbUnsignedExtensionOutputs;
    // Version 6:
    public uint cbClientDataJSON;
    public byte* pbClientDataJSON;
    public uint cbAuthenticationResponseJSON;
    public byte* pbAuthenticationResponseJSON;
}

#endregion

#region P/Invoke - webauthn.dll (WebAuthN client API)

/// <summary>
/// Complete P/Invoke surface for the WebAuthN client APIs declared in webauthn.h.
/// The CTAP-CBOR encode/decode helpers from webauthnplugin.h live in
/// <see cref="WebAuthnPluginApi"/>. All entry points resolve lazily from
/// webauthn.dll at first call.
/// </summary>
internal static unsafe class WebAuthnApi
{
    private const string WebAuthnDll = "webauthn.dll";

    // --- Version / availability -------------------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern uint WebAuthNGetApiVersionNumber();

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
        int* pbIsUserVerifyingPlatformAuthenticatorAvailable);

    // --- MakeCredential / GetAssertion ------------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNAuthenticatorMakeCredential(
        nint hWnd,
        WebAuthnRpEntityInformation* pRpInformation,
        WebAuthnUserEntityInformation* pUserInformation,
        WebAuthnCoseCredentialParameters* pPubKeyCredParams,
        WebAuthnClientData* pWebAuthNClientData,
        WebAuthnAuthenticatorMakeCredentialOptions* pWebAuthNMakeCredentialOptions,
        WebAuthnCredentialAttestation** ppWebAuthNCredentialAttestation);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNAuthenticatorGetAssertion(
        nint hWnd,
        char* pwszRpId,
        WebAuthnClientData* pWebAuthNClientData,
        WebAuthnAuthenticatorGetAssertionOptions* pWebAuthNGetAssertionOptions,
        WebAuthnAssertion** ppWebAuthNAssertion);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreeCredentialAttestation(
        WebAuthnCredentialAttestation* pWebAuthNCredentialAttestation);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreeAssertion(
        WebAuthnAssertion* pWebAuthNAssertion);

    // --- Cancellation ------------------------------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNGetCancellationId(
        Guid* pCancellationId);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNCancelCurrentOperation(
        Guid* pCancellationId);

    // --- Platform credential list (API v4+) -------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNGetPlatformCredentialList(
        WebAuthnGetCredentialsOptions* pGetCredentialsOptions,
        WebAuthnCredentialDetailsList** ppCredentialDetailsList);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreePlatformCredentialList(
        WebAuthnCredentialDetailsList* pCredentialDetailsList);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNDeletePlatformCredential(
        uint cbCredentialId,
        byte* pbCredentialId);

    // --- Authenticator list (API v9+) -------------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNGetAuthenticatorList(
        WebAuthnAuthenticatorDetailsOptions* pWebAuthNGetAuthenticatorListOptions,
        WebAuthnAuthenticatorDetailsList** ppAuthenticatorDetailsList);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern void WebAuthNFreeAuthenticatorList(
        WebAuthnAuthenticatorDetailsList* pAuthenticatorDetailsList);

    // --- Error helpers -----------------------------------------------------

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern char* WebAuthNGetErrorName(int hr);

    [DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
    internal static extern int WebAuthNGetW3CExceptionDOMError(int hr);
}

#endregion
