#include "pch.h"
#include "CredentialCache.h"

HRESULT CredentialCache::AddSingleCredential(
    REFCLSID pluginClsid,
    const std::vector<BYTE>& credentialIdBytes,
    const std::wstring& rpId,
    const std::wstring& rpName,
    const std::vector<BYTE>& userHandleBytes,
    const std::wstring& userName,
    const std::wstring& displayName)
{
    WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS cred = {};
    cred.cbCredentialId      = static_cast<DWORD>(credentialIdBytes.size());
    cred.pbCredentialId      = const_cast<PBYTE>(credentialIdBytes.data());
    cred.pwszRpId            = rpId.c_str();
    cred.pwszRpName          = rpName.empty() ? rpId.c_str() : rpName.c_str();
    cred.cbUserId            = static_cast<DWORD>(userHandleBytes.size());
    cred.pbUserId            = userHandleBytes.empty() ? nullptr : const_cast<PBYTE>(userHandleBytes.data());
    cred.pwszUserName        = userName.c_str();
    cred.pwszUserDisplayName = displayName.empty() ? userName.c_str() : displayName.c_str();

    return WebAuthNPluginAuthenticatorAddCredentials(pluginClsid, 1, &cred);
}

HRESULT CredentialCache::SyncToWindowsCache(REFCLSID pluginClsid)
{
    // Query all credentials from KeePass
    std::string request = R"({"type":"get_credentials","requestId":"sync"})";
    std::string response;
    if (!PipeClient::SendRequest(request, response))
        return S_FALSE; // KeePass not available — not an error

    if (JsonHelper::IsError(response))
        return S_FALSE;

    // Parse the credentials array
    // Note: do NOT call RemoveAllCredentials here — it would invalidate any
    // in-progress authentication flow that Windows started based on the cache. — simple format:
    // {"type":"get_credentials","credentials":[{"credentialId":"...","rpId":"...","userHandle":"...","userName":"..."},...]}
    // We do a simple scan for credential objects
    auto pos = response.find("\"credentials\":");
    if (pos == std::string::npos) return S_OK;

    // Walk through each credential object in the array
    pos = response.find('[', pos);
    if (pos == std::string::npos) return S_OK;
    auto arrayEnd = response.rfind(']');
    if (arrayEnd == std::string::npos) return S_OK;

    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> creds;
    std::vector<std::vector<BYTE>> credIdBufs, userHandleBufs;
    std::vector<std::wstring> rpIds, rpNames, userNames, displayNames;

    auto toWide = [](const std::string& utf8) -> std::wstring
    {
        if (utf8.empty()) return {};
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        std::wstring out(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), wlen);
        if (!out.empty() && out.back() == L'\0') out.pop_back();
        return out;
    };

    auto cur = pos + 1;
    while (cur < arrayEnd)
    {
        auto objStart = response.find('{', cur);
        if (objStart == std::string::npos || objStart >= arrayEnd) break;
        auto objEnd = response.find('}', objStart);
        if (objEnd == std::string::npos || objEnd > arrayEnd) break;
        std::string obj = response.substr(objStart, objEnd - objStart + 1);

        auto credIdStr = JsonHelper::GetStringField(obj, "credentialId");
        auto rpIdStr   = JsonHelper::GetStringField(obj, "rpId");
        auto uhStr     = JsonHelper::GetStringField(obj, "userHandle");
        auto unStr     = JsonHelper::GetStringField(obj, "userName");
        auto titleStr  = JsonHelper::GetStringField(obj, "title");

        if (!credIdStr.empty() && !rpIdStr.empty())
        {
            credIdBufs.push_back(JsonHelper::Base64UrlDecode(credIdStr));
            userHandleBufs.push_back(JsonHelper::Base64UrlDecode(uhStr));
            rpIds.push_back(toWide(rpIdStr));
            rpNames.push_back(toWide(rpIdStr));
            userNames.push_back(toWide(unStr));
            displayNames.push_back(toWide(titleStr.empty() ? rpIdStr : titleStr));
        }
        cur = objEnd + 1;
    }

    // Build the arrays for the API call
    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> credDetails(credIdBufs.size());

    for (size_t i = 0; i < credIdBufs.size(); ++i)
    {
        credDetails[i].cbCredentialId      = static_cast<DWORD>(credIdBufs[i].size());
        credDetails[i].pbCredentialId      = credIdBufs[i].empty() ? nullptr : credIdBufs[i].data();
        credDetails[i].pwszRpId            = rpIds[i].c_str();
        credDetails[i].pwszRpName          = rpNames[i].c_str();
        credDetails[i].cbUserId            = static_cast<DWORD>(userHandleBufs[i].size());
        credDetails[i].pbUserId            = userHandleBufs[i].empty() ? nullptr : userHandleBufs[i].data();
        credDetails[i].pwszUserName        = userNames[i].c_str();
        credDetails[i].pwszUserDisplayName = displayNames[i].c_str();
    }

    if (!credDetails.empty())
    {
        WebAuthNPluginAuthenticatorAddCredentials(pluginClsid, static_cast<DWORD>(credDetails.size()), credDetails.data());
    }

    return S_OK;
}
