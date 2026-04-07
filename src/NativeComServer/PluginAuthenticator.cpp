#include "pch.h"
#include "PluginAuthenticator.h"
#include "PluginRegistration.h"
#include "PipeClient.h"
#include "SignatureVerifier.h"
#include "CredentialCache.h"
#include "JsonHelper.h"
#include <sstream>

// ---------------------------------------------------------------------------
// PluginAuthenticator
// ---------------------------------------------------------------------------

PluginAuthenticator::PluginAuthenticator()
{
    m_cancelled = false;
}

HRESULT STDMETHODCALLTYPE PluginAuthenticator::MakeCredential(
    __RPC__in  PCWEBAUTHN_PLUGIN_OPERATION_REQUEST  pRequest,
    __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE  pResponse) noexcept
{
    if (!pRequest || !pResponse) return E_INVALIDARG;
    *pResponse = {};

    try
    {
        m_cancelled = false;

        // ----------------------------------------------------------------
        // 1. Decode CBOR request
        // ----------------------------------------------------------------
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pDecoded = nullptr;
        RETURN_IF_FAILED(WebAuthNDecodeMakeCredentialRequest(
            pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded));
        auto cleanup = wil::scope_exit([&] { WebAuthNFreeDecodedMakeCredentialRequest(pDecoded); });

        // ----------------------------------------------------------------
        // 2. Verify request signature (best-effort — log but continue if key unavailable)
        // ----------------------------------------------------------------
        std::vector<BYTE> signingKey;
        if (LoadSigningPublicKey(signingKey) && !signingKey.empty())
        {
            RETURN_IF_FAILED(SignatureVerifier::Verify(
                pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                signingKey.data(), static_cast<DWORD>(signingKey.size()),
                pRequest->pbRequestSignature, pRequest->cbRequestSignature));
        }

        // ----------------------------------------------------------------
        // 3. User Verification via Windows Hello
        // ----------------------------------------------------------------
        WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST uvReq{
            .hwnd               = pRequest->hWnd,
            .rguidTransactionId = pRequest->transactionId,
            .pwszUsername       = (pDecoded->pUserInformation && pDecoded->pUserInformation->pwszName)
                                      ? pDecoded->pUserInformation->pwszName : nullptr,
            .pwszDisplayHint    = nullptr,
        };

        DWORD cbUvResp = 0;
        PBYTE pbUvResp = nullptr;
        RETURN_IF_FAILED(WebAuthNPluginPerformUserVerification(&uvReq, &cbUvResp, &pbUvResp));
        auto uvCleanup = wil::scope_exit([&] { WebAuthNPluginFreeUserVerificationResponse(pbUvResp); });

        if (m_cancelled) return NTE_USER_CANCELLED;

        // ----------------------------------------------------------------
        // 4. Build JSON pipe request
        // ----------------------------------------------------------------

        // rpId bytes → UTF-8 string
        std::string rpIdUtf8(
            reinterpret_cast<const char*>(pDecoded->pbRpId),
            pDecoded->cbRpId);

        // Encode userId as base64
        std::string userIdB64;
        if (pDecoded->pUserInformation && pDecoded->pUserInformation->cbId > 0)
            userIdB64 = JsonHelper::Base64Encode(pDecoded->pUserInformation->pbId, pDecoded->pUserInformation->cbId);

        // excludeCredentials
        std::vector<std::string> excludeList;
        for (DWORD i = 0; i < pDecoded->CredentialList.cCredentials; ++i)
        {
            auto* c = pDecoded->CredentialList.ppCredentials[i];
            excludeList.push_back(JsonHelper::Base64Encode(c->pbId, c->cbId));
        }

        std::string requestJson =
            "{\"type\":\"make_credential\","
            "\"requestId\":\"mc1\","
            "\"rpId\":\"" + JsonHelper::Escape(rpIdUtf8) + "\","
            "\"rpName\":\"" + JsonHelper::EscapeW(pDecoded->pRpInformation ? pDecoded->pRpInformation->pwszName : nullptr) + "\","
            "\"userId\":\"" + userIdB64 + "\","
            "\"userName\":\"" + JsonHelper::EscapeW(pDecoded->pUserInformation ? pDecoded->pUserInformation->pwszName : nullptr) + "\","
            "\"userDisplayName\":\"" + JsonHelper::EscapeW(pDecoded->pUserInformation ? pDecoded->pUserInformation->pwszDisplayName : nullptr) + "\","
            "\"excludeCredentials\":" + JsonHelper::StringArray(excludeList) + "}";

        // ----------------------------------------------------------------
        // 5. Send to KeePass plugin
        // ----------------------------------------------------------------
        std::string responseJson;
        if (!PipeClient::SendRequest(requestJson, responseJson))
            return NTE_NOT_FOUND; // KeePass not available

        if (JsonHelper::IsError(responseJson))
        {
            auto code = JsonHelper::GetErrorCode(responseJson);
            if (code == "db_locked")    return HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION);
            if (code == "duplicate")    return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
            if (code == "not_found")    return NTE_NOT_FOUND;
            return E_FAIL;
        }

        // ----------------------------------------------------------------
        // 6. Parse KeePass response
        // ----------------------------------------------------------------
        auto credentialIdB64  = JsonHelper::GetStringField(responseJson, "credentialId");
        auto publicKeyXB64    = JsonHelper::GetStringField(responseJson, "publicKeyX");
        auto publicKeyYB64    = JsonHelper::GetStringField(responseJson, "publicKeyY");
        auto authDataB64      = JsonHelper::GetStringField(responseJson, "authenticatorData");

        if (credentialIdB64.empty() || authDataB64.empty())
            return E_FAIL;

        auto authDataBytes = JsonHelper::Base64Decode(authDataB64);
        auto credIdBytes   = JsonHelper::Base64UrlDecode(credentialIdB64);

        // ----------------------------------------------------------------
        // 7. Assemble WEBAUTHN_CREDENTIAL_ATTESTATION and encode
        // ----------------------------------------------------------------
        WEBAUTHN_CREDENTIAL_ATTESTATION attestation = {};
        attestation.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
        attestation.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
        attestation.pbAuthenticatorData = authDataBytes.data();
        attestation.cbAuthenticatorData = static_cast<DWORD>(authDataBytes.size());
        attestation.cbAttestation = 0;
        attestation.pbAttestation = nullptr;

        DWORD cbEncoded = 0;
        BYTE* pbEncoded = nullptr;
        RETURN_IF_FAILED(WebAuthNEncodeMakeCredentialResponse(&attestation, &cbEncoded, &pbEncoded));

        pResponse->cbEncodedResponse = cbEncoded;
        pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller

        // ----------------------------------------------------------------
        // 8. Update platform credential cache
        // ----------------------------------------------------------------
        if (!credIdBytes.empty())
        {
            std::wstring wrpId, wrpName, wun;
            {
                int n = MultiByteToWideChar(CP_UTF8, 0, rpIdUtf8.c_str(), -1, nullptr, 0);
                wrpId.resize(n); MultiByteToWideChar(CP_UTF8, 0, rpIdUtf8.c_str(), -1, wrpId.data(), n);
                if (!wrpId.empty() && wrpId.back() == L'\0') wrpId.pop_back();
                wrpName = wrpId;
            }
            if (pDecoded->pUserInformation && pDecoded->pUserInformation->pwszName)
                wun = pDecoded->pUserInformation->pwszName;

            std::vector<BYTE> userHandleBytes;
            if (pDecoded->pUserInformation && pDecoded->pUserInformation->cbId > 0)
                userHandleBytes.assign(
                    pDecoded->pUserInformation->pbId,
                    pDecoded->pUserInformation->pbId + pDecoded->pUserInformation->cbId);

            CredentialCache::AddSingleCredential(
                KEEPASS_PASSKEY_PLUGIN_CLSID,
                credIdBytes, wrpId, wrpName, userHandleBytes, wun);
        }

        return S_OK;
    }
    catch (...) { return wil::ResultFromCaughtException(); }
}

HRESULT STDMETHODCALLTYPE PluginAuthenticator::GetAssertion(
    __RPC__in  PCWEBAUTHN_PLUGIN_OPERATION_REQUEST  pRequest,
    __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE  pResponse) noexcept
{
    if (!pRequest || !pResponse) return E_INVALIDARG;
    *pResponse = {};

    try
    {
        m_cancelled = false;

        // ----------------------------------------------------------------
        // 1. Decode CBOR request
        // ----------------------------------------------------------------
        PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST pDecoded = nullptr;
        RETURN_IF_FAILED(WebAuthNDecodeGetAssertionRequest(
            pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded));
        auto cleanup = wil::scope_exit([&] { WebAuthNFreeDecodedGetAssertionRequest(pDecoded); });

        // ----------------------------------------------------------------
        // 2. Verify request signature
        // ----------------------------------------------------------------
        std::vector<BYTE> signingKey;
        if (LoadSigningPublicKey(signingKey) && !signingKey.empty())
        {
            RETURN_IF_FAILED(SignatureVerifier::Verify(
                pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                signingKey.data(), static_cast<DWORD>(signingKey.size()),
                pRequest->pbRequestSignature, pRequest->cbRequestSignature));
        }

        // ----------------------------------------------------------------
        // 3. User Verification
        // ----------------------------------------------------------------
        WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST uvReq{
            .hwnd               = pRequest->hWnd,
            .rguidTransactionId = pRequest->transactionId,
            .pwszUsername       = nullptr,
            .pwszDisplayHint    = nullptr,
        };

        DWORD cbUvResp = 0;
        PBYTE pbUvResp = nullptr;
        RETURN_IF_FAILED(WebAuthNPluginPerformUserVerification(&uvReq, &cbUvResp, &pbUvResp));
        auto uvCleanup = wil::scope_exit([&] { WebAuthNPluginFreeUserVerificationResponse(pbUvResp); });

        if (m_cancelled) return NTE_USER_CANCELLED;

        // ----------------------------------------------------------------
        // 4. Build JSON pipe request
        // ----------------------------------------------------------------
        std::string rpIdUtf8(
            reinterpret_cast<const char*>(pDecoded->pbRpId),
            pDecoded->cbRpId);

        std::string clientDataHashB64 = JsonHelper::Base64Encode(
            pDecoded->pbClientDataHash, pDecoded->cbClientDataHash);

        std::vector<std::string> allowList;
        for (DWORD i = 0; i < pDecoded->CredentialList.cCredentials; ++i)
        {
            auto* c = pDecoded->CredentialList.ppCredentials[i];
            allowList.push_back(JsonHelper::Base64Encode(c->pbId, c->cbId));
        }

        std::string requestJson =
            "{\"type\":\"get_assertion\","
            "\"requestId\":\"ga1\","
            "\"rpId\":\"" + JsonHelper::Escape(rpIdUtf8) + "\","
            "\"clientDataHash\":\"" + clientDataHashB64 + "\","
            "\"allowCredentials\":" + JsonHelper::StringArray(allowList) + "}";

        // ----------------------------------------------------------------
        // 5. Send to KeePass plugin
        // ----------------------------------------------------------------
        std::string responseJson;
        if (!PipeClient::SendRequest(requestJson, responseJson))
            return NTE_NOT_FOUND;

        if (JsonHelper::IsError(responseJson))
        {
            auto code = JsonHelper::GetErrorCode(responseJson);
            if (code == "db_locked") return HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION);
            if (code == "not_found") return NTE_NOT_FOUND;
            return E_FAIL;
        }

        // ----------------------------------------------------------------
        // 6. Parse KeePass response
        // ----------------------------------------------------------------
        auto credentialIdB64 = JsonHelper::GetStringField(responseJson, "credentialId");
        auto authDataB64     = JsonHelper::GetStringField(responseJson, "authenticatorData");
        auto signatureB64    = JsonHelper::GetStringField(responseJson, "signature");
        auto userHandleB64   = JsonHelper::GetStringField(responseJson, "userHandle");

        if (authDataB64.empty() || signatureB64.empty())
            return E_FAIL;

        auto authDataBytes   = JsonHelper::Base64Decode(authDataB64);
        auto signatureBytes  = JsonHelper::Base64Decode(signatureB64);
        auto userHandleBytes = JsonHelper::Base64UrlDecode(userHandleB64);
        auto credIdBytes     = JsonHelper::Base64UrlDecode(credentialIdB64);

        // ----------------------------------------------------------------
        // 7. Assemble WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE and encode
        // ----------------------------------------------------------------
        // We need a WEBAUTHN_CREDENTIAL for the credential ID
        WEBAUTHN_CREDENTIAL cred = {};
        cred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
        cred.cbId = static_cast<DWORD>(credIdBytes.size());
        cred.pbId = credIdBytes.data();
        cred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

        WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE assertionResp = {};
        assertionResp.WebAuthNAssertion.dwVersion    = WEBAUTHN_ASSERTION_CURRENT_VERSION;
        assertionResp.WebAuthNAssertion.Credential   = cred;
        assertionResp.WebAuthNAssertion.cbAuthenticatorData = static_cast<DWORD>(authDataBytes.size());
        assertionResp.WebAuthNAssertion.pbAuthenticatorData = authDataBytes.data();
        assertionResp.WebAuthNAssertion.cbSignature  = static_cast<DWORD>(signatureBytes.size());
        assertionResp.WebAuthNAssertion.pbSignature  = signatureBytes.data();
        assertionResp.WebAuthNAssertion.cbUserId     = static_cast<DWORD>(userHandleBytes.size());
        assertionResp.WebAuthNAssertion.pbUserId     = userHandleBytes.empty() ? nullptr : userHandleBytes.data();

        DWORD cbEncoded = 0;
        BYTE* pbEncoded = nullptr;
        RETURN_IF_FAILED(WebAuthNEncodeGetAssertionResponse(&assertionResp, &cbEncoded, &pbEncoded));

        pResponse->cbEncodedResponse = cbEncoded;
        pResponse->pbEncodedResponse = pbEncoded;

        return S_OK;
    }
    catch (...) { return wil::ResultFromCaughtException(); }
}

HRESULT STDMETHODCALLTYPE PluginAuthenticator::CancelOperation(
    __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST /*pCancelRequest*/) noexcept
{
    m_cancelled = true;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE PluginAuthenticator::GetLockStatus(
    __RPC__out PLUGIN_LOCK_STATUS* pLockStatus) noexcept
{
    if (!pLockStatus) return E_INVALIDARG;

    // Ping KeePass to determine lock status
    std::string response;
    if (!PipeClient::SendRequest(R"({"type":"ping","requestId":"ping"})", response))
    {
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginLocked;
        return S_OK;
    }

    auto status = JsonHelper::GetStringField(response, "status");
    if (status == "ready")
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginUnlocked;
    else
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginLocked;

    return S_OK;
}

HRESULT STDMETHODCALLTYPE PluginAuthenticator::VerifyRequestSignature(
    const BYTE* pbRequest, DWORD cbRequest,
    const BYTE* pbSig, DWORD cbSig)
{
    std::vector<BYTE> signingKey;
    if (!LoadSigningPublicKey(signingKey) || signingKey.empty())
        return S_OK; // key not yet stored — skip (first run scenario)
    return SignatureVerifier::Verify(
        pbRequest, cbRequest,
        signingKey.data(), static_cast<DWORD>(signingKey.size()),
        const_cast<PBYTE>(pbSig), cbSig);
}

// ---------------------------------------------------------------------------
// PluginAuthenticatorFactory
// ---------------------------------------------------------------------------

STDMETHODIMP PluginAuthenticatorFactory::CreateInstance(
    IUnknown* pOuter, REFIID riid, void** ppv) noexcept
{
    if (pOuter) return CLASS_E_NOAGGREGATION;
    auto obj = Make<PluginAuthenticator>();
    if (!obj) return E_OUTOFMEMORY;
    return obj->QueryInterface(riid, ppv);
}

STDMETHODIMP PluginAuthenticatorFactory::LockServer(BOOL fLock) noexcept
{
    if (fLock)
        Module<OutOfProc>::GetModule().IncrementObjectCount();
    else
        Module<OutOfProc>::GetModule().DecrementObjectCount();
    return S_OK;
}
