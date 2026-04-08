#include "pch.h"
#include "CredentialCache.h"

static void Log(const char* fmt, ...)
{
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wchar_t logPath[MAX_PATH];
    wsprintfW(logPath, L"%sPasskeyProvider.log", tempPath);
    FILE* f = nullptr;
    _wfopen_s(&f, logPath, L"a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args; va_start(args, fmt); vfprintf(f, fmt, args); va_end(args);
    fprintf(f, "\n");
    fclose(f);
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

    // Clear the existing cache before repopulating so stale/deleted entries are removed.
    // Use GetAllCredentials + RemoveCredentials rather than RemoveAllCredentials.
    {
        DWORD cExisting = 0;
        PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pExisting = nullptr;
        HRESULT hrGet = WebAuthNPluginAuthenticatorGetAllCredentials(pluginClsid, &cExisting, &pExisting);
        Log("SyncToWindowsCache: GetAllCredentials hr=0x%08X count=%u", hrGet, cExisting);
        if (SUCCEEDED(hrGet) && cExisting > 0 && pExisting != nullptr)
        {
            HRESULT hrRem = WebAuthNPluginAuthenticatorRemoveCredentials(pluginClsid, cExisting, pExisting);
            Log("SyncToWindowsCache: RemoveCredentials hr=0x%08X removed=%u", hrRem, cExisting);
            WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(cExisting, pExisting);
        }
    }

    // Parse the credentials array — simple format:
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
        HRESULT hrAdd = WebAuthNPluginAuthenticatorAddCredentials(pluginClsid, static_cast<DWORD>(credDetails.size()), credDetails.data());
        Log("SyncToWindowsCache: AddCredentials hr=0x%08X added=%zu", hrAdd, credDetails.size());
    }
    else
    {
        Log("SyncToWindowsCache: no credentials to add");
    }

    return S_OK;
}
