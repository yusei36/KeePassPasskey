// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Authenticator.Native;

// =============================================================================
// Complete managed transcription of webauthnplugin.h: the CTAP-CBOR request/
// response structures and their encode/decode entry points, plus the
// WebAuthNPlugin* authenticator-management / autofill-cache / user-verification
// APIs. These types are NOT in the shipped Win32 winmd, so they are bound by hand.
//
// The core WebAuthN data types these structures reuse (WEBAUTHN_RP_ENTITY_INFORMATION,
// WEBAUTHN_ASSERTION, WEBAUTHN_CREDENTIAL_ATTESTATION, ...) live in WebAuthnNative.cs.
// The IPluginAuthenticator COM contract from pluginauthenticator.h lives in
// PluginAuthenticatorNative.cs.
//
// Source: https://github.com/microsoft/webauthn (webauthnplugin.h).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// Same ABI conventions as WebAuthnNative.cs (x64, natural alignment, DWORD->uint,
// LONG/BOOL->int, REFCLSID/REFGUID->Guid*, HWND->nint).
// =============================================================================

#region Enums / constants

#pragma warning disable CA1712 // Members mirror the native header names verbatim.

/// <summary>AUTHENTICATOR_STATE (PLUGIN_AUTHENTICATOR_STATE).</summary>
internal enum AuthenticatorState : int
{
	AuthenticatorState_Disabled = 0,
	AuthenticatorState_Enabled = 1,
}

#pragma warning restore CA1712

/// <summary>WEBAUTHN_PLUGIN_PERFORM_UV_OPERATION_TYPE.</summary>
internal enum WebAuthnPluginPerformUvOperationType : int
{
	PerformUserVerification = 1,
	GetUserVerificationCount = 2,
	GetPublicKey = 3,
}

/// <summary>Structure version constants from webauthnplugin.h.</summary>
internal static class WebAuthnPluginConstants
{
	public const uint CtapCborAuthenticatorOptionsCurrentVersion = 1;
	public const uint CtapCborEccPublicKeyCurrentVersion = 1;
	public const uint CtapCborHmacSaltExtensionCurrentVersion = 1;
	public const uint CtapCborMakeCredentialRequestCurrentVersion = 1;
	public const uint CtapCborGetAssertionRequestCurrentVersion = 1;
}

#endregion

#region CTAP-CBOR request/response structures

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborAuthenticatorOptions
{
	public uint dwVersion;
	public int lUp;                 // +1 true / 0 undefined / -1 false
	public int lUv;
	public int lRequireResidentKey;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborEccPublicKey
{
	public uint dwVersion;
	public int lKty;
	public int lAlg;
	public int lCrv;
	public uint cbX;
	public byte* pbX;
	public uint cbY;
	public byte* pbY;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborHmacSaltExtension
{
	public uint dwVersion;
	public WebAuthnCtapCborEccPublicKey* pKeyAgreement;
	public uint cbEncryptedSalt;
	public byte* pbEncryptedSalt;
	public uint cbSaltAuth;
	public byte* pbSaltAuth;
}

/// <summary>WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST (full declaration).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborMakeCredentialRequest
{
	public uint dwVersion;
	public uint cbRpId;
	public byte* pbRpId;
	public uint cbClientDataHash;
	public byte* pbClientDataHash;
	public WebAuthnRpEntityInformation* pRpInformation;
	public WebAuthnUserEntityInformation* pUserInformation;
	public WebAuthnCoseCredentialParameters WebAuthNCredentialParameters;
	public WebAuthnCredentialList CredentialList;
	public uint cbCborExtensionsMap;
	public byte* pbCborExtensionsMap;
	public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
	public int fEmptyPinAuth; // BOOL
	public uint cbPinAuth;
	public byte* pbPinAuth;
	public int lHmacSecretExt;
	public WebAuthnCtapCborHmacSaltExtension* pHmacSecretMcExtension;
	public int lPrfExt;
	public uint cbHmacSecretSaltValues;
	public byte* pbHmacSecretSaltValues;
	public uint dwCredProtect;
	public uint dwPinProtocol;
	public uint dwEnterpriseAttestation;
	public uint cbCredBlobExt;
	public byte* pbCredBlobExt;
	public int lLargeBlobKeyExt;
	public uint dwLargeBlobSupport;
	public int lMinPinLengthExt;
	public uint cbJsonExt;
	public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST (full declaration).</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionRequest
{
	public uint dwVersion;
	public char* pwszRpId;
	public uint cbRpId;
	public byte* pbRpId;
	public uint cbClientDataHash;
	public byte* pbClientDataHash;
	public WebAuthnCredentialList CredentialList;
	public uint cbCborExtensionsMap;
	public byte* pbCborExtensionsMap;
	public WebAuthnCtapCborAuthenticatorOptions* pAuthenticatorOptions;
	public int fEmptyPinAuth; // BOOL
	public uint cbPinAuth;
	public byte* pbPinAuth;
	public WebAuthnCtapCborHmacSaltExtension* pHmacSaltExtension;
	public uint cbHmacSecretSaltValues;
	public byte* pbHmacSecretSaltValues;
	public uint dwPinProtocol;
	public int lCredBlobExt;
	public int lLargeBlobKeyExt;
	public uint dwCredLargeBlobOperation;
	public uint cbCredLargeBlobCompressed;
	public byte* pbCredLargeBlobCompressed;
	public uint dwCredLargeBlobOriginalSize;
	public uint cbJsonExt;
	public byte* pbJsonExt;
}

/// <summary>WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnCtapCborGetAssertionResponse
{
	public WebAuthnAssertion WebAuthNAssertion;          // 176 bytes
	public WebAuthnUserEntityInformation* pUserInformation;
	public uint dwNumberOfCredentials;
	public int lUserSelected;                            // LONG
	public uint cbLargeBlobKey;
	public byte* pbLargeBlobKey;
	public uint cbUnsignedExtensionOutputs;
	public byte* pbUnsignedExtensionOutputs;
}

#endregion

#region Plugin-management structures

/// <summary>
/// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS - passed to WebAuthNPluginAddAuthenticator.
/// rclsid is REFCLSID = const CLSID* (pointer on x64).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions
{
	public char* pwszAuthenticatorName;  // LPCWSTR
	public Guid* rclsid;                 // REFCLSID
	public char* pwszPluginRpId;         // LPCWSTR (required for a nested WebAuthN call originating from a plugin)
	public char* pwszLightThemeLogoSvg;  // LPCWSTR (optional)
	public char* pwszDarkThemeLogoSvg;   // LPCWSTR (optional)
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;    // CTAP CBOR authenticatorGetInfo
	public uint cSupportedRpIds;         // 0 => all RPs supported
	public char** ppwszSupportedRpIds;   // const LPCWSTR*
}

/// <summary>WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorResponse
{
	public uint cbOpSignPubKey;
	public byte* pbOpSignPubKey;
}

/// <summary>WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUpdateAuthenticatorDetails
{
	public char* pwszAuthenticatorName;
	public Guid* rclsid;                 // REFCLSID
	public Guid* rclsidNew;              // REFCLSID
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
}

/// <summary>
/// WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS - one entry in the Windows autofill cache.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCredentialDetails
{
	public uint cbCredentialId;
	public byte* pbCredentialId;
	public char* pwszRpId;               // LPCWSTR
	public char* pwszRpName;             // LPCWSTR
	public uint cbUserId;
	public byte* pbUserId;
	public char* pwszUserName;           // LPCWSTR
	public char* pwszUserDisplayName;    // LPCWSTR
}

/// <summary>
/// WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST - passed to WebAuthNPluginPerformUserVerification.
/// rguidTransactionId is REFGUID = const GUID* (pointer, not inline value).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUserVerificationRequest
{
	public nint hwnd;                 // HWND
	public Guid* rguidTransactionId;  // REFGUID
	public char* pwszUsername;        // LPCWSTR (optional)
	public char* pwszDisplayHint;     // LPCWSTR (optional)
}

#endregion

#region Plugin-management structures (v2 - finalized in KB5089573, OS builds 26200.8524 / 26100.8524)

/// <summary>WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginAddAuthenticatorOptions2
{
	public char* pwszAuthenticatorName;
	public Guid* pClsid;                 // const CLSID*
	public char* pwszPluginRpId;         // required for a nested WebAuthN call originating from a plugin
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
	public char* pwszUserVerificationKeyName; // name for KeyCredentialManager.RequestCreateAsync (optional)
}

/// <summary>WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUpdateAuthenticatorDetails2
{
	public char* pwszAuthenticatorName;
	public Guid* pClsid;                 // const CLSID*
	public Guid* pClsidNew;              // const CLSID*
	public char* pwszLightThemeLogoSvg;
	public char* pwszDarkThemeLogoSvg;
	public uint cbAuthenticatorInfo;
	public byte* pbAuthenticatorInfo;
	public uint cSupportedRpIds;
	public char** ppwszSupportedRpIds;
	public char* pwszUserVerificationKeyName; // name for KeyCredentialManager.RequestCreateAsync (optional, NULL removes this)
}

/// <summary>WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST_2.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginUserVerificationRequest2
{
	public nint hwnd;                 // HWND
	public Guid* pGuidTransactionId;  // const GUID*
	public char* pwszUsername;
	public char* pwszDisplayHint;
	public uint cbBufferToSign;
	public byte* pbBufferToSign;      // custom buffer signed by the UV key (optional; not hashed by the API)
}

#endregion

#region P/Invoke - webauthn.dll (plugin APIs + CTAP-CBOR encode/decode)

/// <summary>
/// Complete P/Invoke surface for webauthnplugin.h: the WebAuthNPlugin* management,
/// autofill-cache and user-verification APIs, plus the CTAP-CBOR encode/decode
/// helpers. All entry points resolve lazily from webauthn.dll at first call.
///
/// The *2 entry points (finalized in KB5089573) require recent Windows builds
/// (26200.8524 / 26100.8524); because P/Invoke resolves entry points lazily at
/// first call, declaring them is harmless on older builds until actually invoked.
/// </summary>
internal static unsafe class WebAuthnPluginApi
{
	private const string WebAuthnDll = "webauthn.dll";

	// --- CTAP-CBOR encode / decode ----------------------------------------

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

	// --- Authenticator registration ---------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetAuthenticatorState(
		in Guid rclsid,
		AuthenticatorState* pluginAuthenticatorState);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAddAuthenticator(
		WebAuthnPluginAddAuthenticatorOptions* pPluginAddAuthenticatorOptions,
		WebAuthnPluginAddAuthenticatorResponse** ppPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAddAuthenticator2(
		WebAuthnPluginAddAuthenticatorOptions2* pPluginAddAuthenticatorOptions,
		WebAuthnPluginAddAuthenticatorResponse** ppPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreeAddAuthenticatorResponse(
		WebAuthnPluginAddAuthenticatorResponse* pPluginAddAuthenticatorResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginRemoveAuthenticator(in Guid rclsid);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUpdateAuthenticatorDetails(
		WebAuthnPluginUpdateAuthenticatorDetails* pPluginUpdateAuthenticatorDetails);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUpdateAuthenticatorDetails2(
		WebAuthnPluginUpdateAuthenticatorDetails2* pPluginUpdateAuthenticatorDetails);

	// --- Autofill credential cache ----------------------------------------

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
	internal static extern int WebAuthNPluginAuthenticatorRemoveAllCredentials(in Guid rclsid);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginAuthenticatorGetAllCredentials(
		in Guid rclsid,
		uint* pcCredentialDetails,
		WebAuthnPluginCredentialDetails** ppCredentialDetailsArray);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(
		uint cCredentialDetails,
		WebAuthnPluginCredentialDetails* pCredentialDetailsArray);

	// --- Windows Hello user verification ----------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginPerformUserVerification(
		WebAuthnPluginUserVerificationRequest* pPluginUserVerification,
		uint* pcbResponse,
		byte** ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginPerformUserVerification2(
		WebAuthnPluginUserVerificationRequest2* pPluginUserVerification,
		uint* pcbResponse,
		byte** ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreeUserVerificationResponse(byte* ppbResponse);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetUserVerificationCount(
		in Guid rclsid,
		uint* pdwVerificationCount);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetUserVerificationPublicKey(
		in Guid rclsid,
		uint* pcbPublicKey,
		byte** ppbPublicKey); // free with WebAuthNPluginFreePublicKeyResponse

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginGetOperationSigningPublicKey(
		in Guid rclsid,
		uint* pcbOpSignPubKey,
		byte** ppbOpSignPubKey); // free with WebAuthNPluginFreePublicKeyResponse

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern void WebAuthNPluginFreePublicKeyResponse(byte* pbOpSignPubKey);

	// --- Status-change notifications --------------------------------------

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginRegisterStatusChangeCallback(
		delegate* unmanaged[Stdcall]<void*, void> callback,
		void* context,
		in Guid rclsid,
		uint* pdwRegister);

	[DllImport(WebAuthnDll, CallingConvention = CallingConvention.Winapi)]
	internal static extern int WebAuthNPluginUnregisterStatusChangeCallback(uint* pdwRegister);
}

#endregion
