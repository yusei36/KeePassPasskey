#pragma once
#include <windows.h>
#include <webauthn.h>
#include <webauthnplugin.h>
#include <wil/result.h>

// Require Windows SDK 10.0.26100.7175+
template<typename, typename = void> constexpr bool is_type_complete_v = false;
template<typename T> constexpr bool is_type_complete_v<T, std::void_t<decltype(sizeof(T))>> = true;
static_assert(is_type_complete_v<struct _WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS>,
    "Windows SDK 10.0.26100.7175+ required");

namespace {
    inline HMODULE GetWebAuthnDll()
    {
        static wil::unique_hmodule s_dll(LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
        return s_dll.get();
    }
}

inline HRESULT WINAPI WebAuthNPluginAddAuthenticator(
    _In_ PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS pOptions,
    _Outptr_result_maybenull_ PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE* ppResponse)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginAddAuthenticator);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(pOptions, ppResponse);
}

inline void WINAPI WebAuthNPluginFreeAddAuthenticatorResponse(
    _In_opt_ PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE p)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginFreeAddAuthenticatorResponse);
    if (s_fn) s_fn(p);
}

inline HRESULT WINAPI WebAuthNPluginRemoveAuthenticator(_In_ REFCLSID rclsid)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginRemoveAuthenticator);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid);
}

inline HRESULT WINAPI WebAuthNPluginGetAuthenticatorState(
    _In_ REFCLSID rclsid,
    _Out_ AUTHENTICATOR_STATE* pState)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginGetAuthenticatorState);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid, pState);
}

inline HRESULT WINAPI WebAuthNPluginGetOperationSigningPublicKey(
    _In_ REFCLSID rclsid,
    _Out_ DWORD* pcbKey,
    _Outptr_result_buffer_maybenull_(*pcbKey) PBYTE* ppbKey)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginGetOperationSigningPublicKey);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid, pcbKey, ppbKey);
}

inline void WINAPI WebAuthNPluginFreePublicKeyResponse(_In_opt_ PBYTE pb)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginFreePublicKeyResponse);
    if (s_fn) s_fn(pb);
}

inline HRESULT WINAPI WebAuthNPluginGetUserVerificationPublicKey(
    _In_ REFCLSID rclsid,
    _Out_ DWORD* pcbKey,
    _Outptr_result_bytebuffer_(*pcbKey) PBYTE* ppbKey)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginGetUserVerificationPublicKey);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid, pcbKey, ppbKey);
}

inline HRESULT WINAPI WebAuthNPluginPerformUserVerification(
    _In_ PCWEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST pReq,
    _Out_ DWORD* pcbResp,
    _Outptr_result_bytebuffer_maybenull_(*pcbResp) PBYTE* ppbResp)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginPerformUserVerification);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(pReq, pcbResp, ppbResp);
}

inline void WINAPI WebAuthNPluginFreeUserVerificationResponse(_In_opt_ PBYTE pb)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginFreeUserVerificationResponse);
    if (s_fn) s_fn(pb);
}

inline HRESULT WINAPI WebAuthNDecodeMakeCredentialRequest(
    _In_ DWORD cbEncoded,
    _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
    _Outptr_ PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST* ppReq)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNDecodeMakeCredentialRequest);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(cbEncoded, pbEncoded, ppReq);
}

inline void WINAPI WebAuthNFreeDecodedMakeCredentialRequest(
    _In_opt_ PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST p)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNFreeDecodedMakeCredentialRequest);
    if (s_fn) s_fn(p);
}

inline HRESULT WINAPI WebAuthNEncodeMakeCredentialResponse(
    _In_ PCWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation,
    _Out_ DWORD* pcbResp,
    _Outptr_result_buffer_maybenull_(*pcbResp) BYTE** ppbResp)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNEncodeMakeCredentialResponse);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(pAttestation, pcbResp, ppbResp);
}

inline HRESULT WINAPI WebAuthNDecodeGetAssertionRequest(
    _In_ DWORD cbEncoded,
    _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
    _Outptr_ PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST* ppReq)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNDecodeGetAssertionRequest);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(cbEncoded, pbEncoded, ppReq);
}

inline void WINAPI WebAuthNFreeDecodedGetAssertionRequest(
    _In_opt_ PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST p)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNFreeDecodedGetAssertionRequest);
    if (s_fn) s_fn(p);
}

inline HRESULT WINAPI WebAuthNEncodeGetAssertionResponse(
    _In_ PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE pResp,
    _Out_ DWORD* pcbOut,
    _Outptr_result_buffer_maybenull_(*pcbOut) BYTE** ppbOut)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNEncodeGetAssertionResponse);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(pResp, pcbOut, ppbOut);
}

inline HRESULT WINAPI WebAuthNPluginAuthenticatorAddCredentials(
    _In_ REFCLSID rclsid,
    _In_ DWORD cCreds,
    _In_reads_(cCreds) PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCreds)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginAuthenticatorAddCredentials);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid, cCreds, pCreds);
}

inline HRESULT WINAPI WebAuthNPluginAuthenticatorRemoveAllCredentials(_In_ REFCLSID rclsid)
{
    static auto s_fn = GetProcAddressByFunctionDeclaration(GetWebAuthnDll(), WebAuthNPluginAuthenticatorRemoveAllCredentials);
    RETURN_HR_IF_NULL(E_NOTIMPL, s_fn);
    return s_fn(rclsid);
}
