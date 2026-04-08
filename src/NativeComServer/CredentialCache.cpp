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

    // ----------------------------------------------------------------
    // Parse KeePass credentials
    // ----------------------------------------------------------------
    auto toWide = [](const std::string& utf8) -> std::wstring
    {
        if (utf8.empty()) return {};
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        std::wstring out(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, out.data(), wlen);
        if (!out.empty() && out.back() == L'\0') out.pop_back();
        return out;
    };

    std::vector<std::vector<BYTE>> credIdBufs, userHandleBufs;
    std::vector<std::wstring> rpIds, rpNames, userNames, displayNames;

    auto pos = response.find("\"credentials\":");
    if (pos != std::string::npos)
    {
        pos = response.find('[', pos);
        auto arrayEnd = (pos != std::string::npos) ? response.rfind(']') : std::string::npos;
        auto cur = (pos != std::string::npos) ? pos + 1 : std::string::npos;

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
    }

    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> kpCreds(credIdBufs.size());
    for (size_t i = 0; i < credIdBufs.size(); ++i)
    {
        kpCreds[i].cbCredentialId      = static_cast<DWORD>(credIdBufs[i].size());
        kpCreds[i].pbCredentialId      = credIdBufs[i].empty() ? nullptr : credIdBufs[i].data();
        kpCreds[i].pwszRpId            = rpIds[i].c_str();
        kpCreds[i].pwszRpName          = rpNames[i].c_str();
        kpCreds[i].cbUserId            = static_cast<DWORD>(userHandleBufs[i].size());
        kpCreds[i].pbUserId            = userHandleBufs[i].empty() ? nullptr : userHandleBufs[i].data();
        kpCreds[i].pwszUserName        = userNames[i].c_str();
        kpCreds[i].pwszUserDisplayName = displayNames[i].c_str();
    }

    // ----------------------------------------------------------------
    // Get current Windows cache
    // ----------------------------------------------------------------
    DWORD cExisting = 0;
    PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pExisting = nullptr;
    HRESULT hrGet = WebAuthNPluginAuthenticatorGetAllCredentials(pluginClsid, &cExisting, &pExisting);
    Log("SyncToWindowsCache: GetAllCredentials hr=0x%08X count=%u", hrGet, cExisting);

    // ----------------------------------------------------------------
    // Diff: compare by credential ID, then by fields
    // ----------------------------------------------------------------
    auto bytesEq = [](const BYTE* a, DWORD ca, const BYTE* b, DWORD cb) -> bool
    {
        return ca == cb && (ca == 0 || memcmp(a, b, ca) == 0);
    };
    auto wstrEq = [](LPCWSTR a, LPCWSTR b) -> bool
    {
        if (!a && !b) return true;
        if (!a || !b) return false;
        return wcscmp(a, b) == 0;
    };
    auto credEq = [&](const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS& a,
                      const WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS& b) -> bool
    {
        return bytesEq(a.pbCredentialId, a.cbCredentialId, b.pbCredentialId, b.cbCredentialId)
            && wstrEq(a.pwszRpId, b.pwszRpId)
            && wstrEq(a.pwszUserName, b.pwszUserName)
            && wstrEq(a.pwszUserDisplayName, b.pwszUserDisplayName)
            && bytesEq(a.pbUserId, a.cbUserId, b.pbUserId, b.cbUserId);
    };

    // Windows entries not in KeePass (or changed) → remove
    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> toRemove;
    if (SUCCEEDED(hrGet) && cExisting > 0 && pExisting != nullptr)
    {
        for (DWORD i = 0; i < cExisting; ++i)
        {
            bool matchedAndSame = false;
            for (const auto& kp : kpCreds)
            {
                if (bytesEq(pExisting[i].pbCredentialId, pExisting[i].cbCredentialId,
                            kp.pbCredentialId, kp.cbCredentialId))
                {
                    matchedAndSame = credEq(pExisting[i], kp);
                    break;
                }
            }
            if (!matchedAndSame)
                toRemove.push_back(pExisting[i]);
        }
    }

    // KeePass entries not in Windows (or changed) → add
    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> toAdd;
    for (const auto& kp : kpCreds)
    {
        bool matchedAndSame = false;
        if (SUCCEEDED(hrGet) && cExisting > 0 && pExisting != nullptr)
        {
            for (DWORD i = 0; i < cExisting; ++i)
            {
                if (bytesEq(kp.pbCredentialId, kp.cbCredentialId,
                            pExisting[i].pbCredentialId, pExisting[i].cbCredentialId))
                {
                    matchedAndSame = credEq(kp, pExisting[i]);
                    break;
                }
            }
        }
        if (!matchedAndSame)
            toAdd.push_back(kp);
    }

    // ----------------------------------------------------------------
    // Apply changes — free pExisting after remove (pointers still valid until then)
    // ----------------------------------------------------------------
    if (!toRemove.empty())
    {
        HRESULT hrRem = WebAuthNPluginAuthenticatorRemoveCredentials(
            pluginClsid, static_cast<DWORD>(toRemove.size()), toRemove.data());
        Log("SyncToWindowsCache: RemoveCredentials hr=0x%08X removed=%zu", hrRem, toRemove.size());
    }

    if (pExisting)
        WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(cExisting, pExisting);

    if (!toAdd.empty())
    {
        HRESULT hrAdd = WebAuthNPluginAuthenticatorAddCredentials(
            pluginClsid, static_cast<DWORD>(toAdd.size()), toAdd.data());
        Log("SyncToWindowsCache: AddCredentials hr=0x%08X added=%zu", hrAdd, toAdd.size());
    }

    Log("SyncToWindowsCache: done removed=%zu added=%zu unchanged=%zu",
        toRemove.size(), toAdd.size(), kpCreds.size() - toAdd.size());

    return S_OK;
}
