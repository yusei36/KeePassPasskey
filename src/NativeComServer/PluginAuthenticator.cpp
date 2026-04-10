#include "pch.h"
#include "PluginAuthenticator.h"
#include "PluginRegistration.h"
#include "PipeClient.h"
#include "SignatureVerifier.h"
#include "CredentialCache.h"
#include "JsonHelper.h"
#include "Log.h"
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
        Log("MakeCredential: entry");

        // ----------------------------------------------------------------
        // 1. Decode CBOR request
        // ----------------------------------------------------------------
        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pDecoded = nullptr;
        HRESULT hr1 = WebAuthNDecodeMakeCredentialRequest(
            pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
        Log("MakeCredential: WebAuthNDecodeMakeCredentialRequest hr=0x%08X", hr1);
        RETURN_IF_FAILED(hr1);
        auto cleanup = wil::scope_exit([&] { WebAuthNFreeDecodedMakeCredentialRequest(pDecoded); });

        // ----------------------------------------------------------------
        // 2. Verify request signature
        // ----------------------------------------------------------------
        std::vector<BYTE> signingKey;
        if (LoadSigningPublicKey(signingKey) && !signingKey.empty())
        {
            HRESULT hrSig = SignatureVerifier::Verify(
                pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                signingKey.data(), static_cast<DWORD>(signingKey.size()),
                pRequest->pbRequestSignature, pRequest->cbRequestSignature);
            Log("MakeCredential: SignatureVerifier::Verify hr=0x%08X", hrSig);
            RETURN_IF_FAILED(hrSig);
        }
        else
        {
            //TODO only if debug?
            Log("MakeCredential: no signing key, skipping signature verification");
        }

        // ----------------------------------------------------------------
        // 3. User Verification
        // ----------------------------------------------------------------
        Log("MakeCredential: native user verification disabled");

        if (m_cancelled) { Log("MakeCredential: cancelled"); return NTE_USER_CANCELLED; }

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

        // excludeCredentials — must be base64url to match stored credential IDs
        std::vector<std::string> excludeList;
        for (DWORD i = 0; i < pDecoded->CredentialList.cCredentials; ++i)
        {
            auto* c = pDecoded->CredentialList.ppCredentials[i];
            excludeList.push_back(JsonHelper::Base64UrlEncode(c->pbId, c->cbId));
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
        Log("MakeCredential: sending pipe request: %s", requestJson.c_str());
        std::string responseJson;
        if (!PipeClient::SendRequest(requestJson, responseJson))
        {
            Log("MakeCredential: PipeClient::SendRequest failed (KeePass not available)");
            return NTE_NOT_FOUND; // KeePass not available
        }
        Log("MakeCredential: pipe response: %s", responseJson.c_str());

        if (JsonHelper::IsError(responseJson))
        {
            auto code = JsonHelper::GetErrorCode(responseJson);
            Log("MakeCredential: KeePass error: %s", code.c_str());
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
        Log("MakeCredential: credentialId=%s authData len=%zu", credentialIdB64.c_str(), authDataB64.size());

        if (credentialIdB64.empty() || authDataB64.empty())
        {
            Log("MakeCredential: missing credentialId or authData");
            return E_FAIL;
        }

        auto authDataBytes = JsonHelper::Base64Decode(authDataB64);
        auto credIdBytes   = JsonHelper::Base64UrlDecode(credentialIdB64);
        Log("MakeCredential: authData bytes=%zu credId bytes=%zu", authDataBytes.size(), credIdBytes.size());

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
        Log("MakeCredential: calling WebAuthNEncodeMakeCredentialResponse, dwVersion=%u", attestation.dwVersion);
        HRESULT hrEnc = WebAuthNEncodeMakeCredentialResponse(&attestation, &cbEncoded, &pbEncoded);
        Log("MakeCredential: WebAuthNEncodeMakeCredentialResponse hr=0x%08X cbEncoded=%u", hrEnc, cbEncoded);
        RETURN_IF_FAILED(hrEnc);

        pResponse->cbEncodedResponse = cbEncoded;
        pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller

        // ----------------------------------------------------------------
        // 8. Update platform credential cache
        // ----------------------------------------------------------------
        CredentialCache::SyncToWindowsCache(KEEPASS_PASSKEY_PLUGIN_CLSID);

        Log("MakeCredential: success");
        return S_OK;
    }
    catch (...)
    {
        HRESULT hrCaught = wil::ResultFromCaughtException();
        Log("MakeCredential: caught exception hr=0x%08X", hrCaught);
        return hrCaught;
    }
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
        Log("GetAssertion: entry");

        // ----------------------------------------------------------------
        // 1. Decode CBOR request
        // ----------------------------------------------------------------
        PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST pDecoded = nullptr;
        HRESULT hr1 = WebAuthNDecodeGetAssertionRequest(
            pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
        Log("GetAssertion: WebAuthNDecodeGetAssertionRequest hr=0x%08X", hr1);
        RETURN_IF_FAILED(hr1);
        auto cleanup = wil::scope_exit([&] { WebAuthNFreeDecodedGetAssertionRequest(pDecoded); });

        // ----------------------------------------------------------------
        // 2. Verify request signature
        // ----------------------------------------------------------------
        std::vector<BYTE> signingKey;
        if (LoadSigningPublicKey(signingKey) && !signingKey.empty())
        {
            HRESULT hrSig = SignatureVerifier::Verify(
                pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                signingKey.data(), static_cast<DWORD>(signingKey.size()),
                pRequest->pbRequestSignature, pRequest->cbRequestSignature);
            Log("GetAssertion: SignatureVerifier::Verify hr=0x%08X", hrSig);
            RETURN_IF_FAILED(hrSig);
        }
        else
        {
            //TODO only if debug?
            Log("GetAssertion: no signing key, skipping signature verification");
        }

        // ----------------------------------------------------------------
        // 3. Extract rpId, allowCredentials, clientDataHash
        // ----------------------------------------------------------------
        std::string rpIdUtf8(
            reinterpret_cast<const char*>(pDecoded->pbRpId),
            pDecoded->cbRpId);
        Log("GetAssertion: rpId=%s allowCredentials=%u", rpIdUtf8.c_str(), pDecoded->CredentialList.cCredentials);

        std::string clientDataHashB64 = JsonHelper::Base64Encode(
            pDecoded->pbClientDataHash, pDecoded->cbClientDataHash);

        // allowCredentials — must be base64url to match stored credential IDs
        std::vector<std::string> allowList;
        for (DWORD i = 0; i < pDecoded->CredentialList.cCredentials; ++i)
        {
            auto* c = pDecoded->CredentialList.ppCredentials[i];
            allowList.push_back(JsonHelper::Base64UrlEncode(c->pbId, c->cbId));
        }
        std::string allowCredentialsJson = JsonHelper::StringArray(allowList);

        // ----------------------------------------------------------------
        // 4. User Verification
        // ----------------------------------------------------------------
        Log("GetAssertion: native user verification disabled");

        if (m_cancelled) { Log("GetAssertion: cancelled"); return NTE_USER_CANCELLED; }

        // ----------------------------------------------------------------
        // 5. Build JSON pipe request
        // ----------------------------------------------------------------
        std::string requestJson =
            "{\"type\":\"get_assertion\","
            "\"requestId\":\"ga1\","
            "\"rpId\":\"" + JsonHelper::Escape(rpIdUtf8) + "\","
            "\"clientDataHash\":\"" + clientDataHashB64 + "\","
            "\"allowCredentials\":" + allowCredentialsJson + "}";

        // ----------------------------------------------------------------
        // 6. Send to KeePass plugin
        // ----------------------------------------------------------------
        Log("GetAssertion: sending pipe request: %s", requestJson.c_str());
        std::string responseJson;
        if (!PipeClient::SendRequest(requestJson, responseJson))
        {
            Log("GetAssertion: PipeClient::SendRequest failed");
            return NTE_NOT_FOUND;
        }
        Log("GetAssertion: pipe response: %s", responseJson.c_str());

        if (JsonHelper::IsError(responseJson))
        {
            auto code = JsonHelper::GetErrorCode(responseJson);
            Log("GetAssertion: KeePass error: %s", code.c_str());
            if (code == "db_locked") return HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION);
            if (code == "not_found") return NTE_NOT_FOUND;
            return E_FAIL;
        }

        // ----------------------------------------------------------------
        // 7. Parse KeePass response
        // ----------------------------------------------------------------
        auto credentialIdB64 = JsonHelper::GetStringField(responseJson, "credentialId");
        auto authDataB64     = JsonHelper::GetStringField(responseJson, "authenticatorData");
        auto signatureB64    = JsonHelper::GetStringField(responseJson, "signature");
        auto userHandleB64   = JsonHelper::GetStringField(responseJson, "userHandle");
        auto userNameUtf8    = JsonHelper::GetStringField(responseJson, "userName");
        auto userDisplayUtf8 = JsonHelper::GetStringField(responseJson, "userDisplayName");
        Log("GetAssertion: credentialId=%s authData len=%zu signature len=%zu",
            credentialIdB64.c_str(), authDataB64.size(), signatureB64.size());

        if (authDataB64.empty() || signatureB64.empty())
        {
            Log("GetAssertion: missing authData or signature");
            return E_FAIL;
        }

        auto authDataBytes   = JsonHelper::Base64Decode(authDataB64);
        auto signatureBytes  = JsonHelper::Base64Decode(signatureB64);
        auto userHandleBytes = JsonHelper::Base64UrlDecode(userHandleB64);
        auto credIdBytes     = JsonHelper::Base64UrlDecode(credentialIdB64);
        Log("GetAssertion: authData=%zu sig=%zu userHandle=%zu credId=%zu bytes",
            authDataBytes.size(), signatureBytes.size(), userHandleBytes.size(), credIdBytes.size());

        auto utf8ToWide = [](const std::string& utf8) -> std::wstring
        {
            if (utf8.empty()) return {};
            int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
            if (wlen <= 0) return {};
            std::wstring out(wlen, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), wlen);
            if (!out.empty() && out.back() == L'\0') out.pop_back();
            return out;
        };
        std::wstring userNameWide = utf8ToWide(userNameUtf8);
        std::wstring userDisplayWide = utf8ToWide(userDisplayUtf8);

        // ----------------------------------------------------------------
        // 8. Assemble WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE and encode
        // ----------------------------------------------------------------
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
        WEBAUTHN_USER_ENTITY_INFORMATION userInfo = {};
        userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
        userInfo.cbId = static_cast<DWORD>(userHandleBytes.size());
        userInfo.pbId = userHandleBytes.empty() ? nullptr : userHandleBytes.data();
        userInfo.pwszName = userNameWide.empty() ? nullptr : userNameWide.c_str();
        userInfo.pwszIcon = nullptr;
        userInfo.pwszDisplayName = userDisplayWide.empty() ? userInfo.pwszName : userDisplayWide.c_str();
        assertionResp.pUserInformation = userInfo.pbId ? &userInfo : nullptr;
        assertionResp.dwNumberOfCredentials = 1;
        assertionResp.lUserSelected = TRUE;

        DWORD cbEncoded = 0;
        BYTE* pbEncoded = nullptr;
        Log("GetAssertion: calling WebAuthNEncodeGetAssertionResponse");
        HRESULT hrEnc = WebAuthNEncodeGetAssertionResponse(&assertionResp, &cbEncoded, &pbEncoded);
        Log("GetAssertion: WebAuthNEncodeGetAssertionResponse hr=0x%08X cbEncoded=%u", hrEnc, cbEncoded);
        RETURN_IF_FAILED(hrEnc);

        pResponse->cbEncodedResponse = cbEncoded;
        pResponse->pbEncodedResponse = pbEncoded;

        Log("GetAssertion: success");
        return S_OK;
    }
    catch (...)
    {
        HRESULT hrCaught = wil::ResultFromCaughtException();
        Log("GetAssertion: caught exception hr=0x%08X", hrCaught);
        return hrCaught;
    }
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
    bool pipeOk = PipeClient::SendRequest(R"({"type":"ping","requestId":"ping"})", response);
    Log("GetLockStatus: pipe ok=%d response=%s", pipeOk ? 1 : 0, response.c_str());

    if (!pipeOk)
    {
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginLocked;
        return S_OK;
    }

    auto status = JsonHelper::GetStringField(response, "status");
    if (status == "ready")
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginUnlocked;
    else
        *pLockStatus = PLUGIN_LOCK_STATUS::PluginLocked;

    Log("GetLockStatus: status=%s lockStatus=%d", status.c_str(), (int)*pLockStatus);
    return S_OK;
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
