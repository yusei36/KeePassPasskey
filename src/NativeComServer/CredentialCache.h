#pragma once
#include "pch.h"
#include "PipeClient.h"
#include "JsonHelper.h"
#include <vector>
#include <string>

/// Synchronizes KeePass credentials to the Windows platform autofill cache.
class CredentialCache
{
public:
    /// Query KeePass for all credentials and push them to the platform cache.
    static HRESULT SyncToWindowsCache(REFCLSID pluginClsid);

    /// Push a single newly-created credential to the Windows cache.
    /// credentialIdBytes: raw credential ID bytes
    /// rpId, rpName: relying party
    /// userHandle: raw user handle bytes
    /// userName: UTF-8 display name
    static HRESULT AddSingleCredential(
        REFCLSID pluginClsid,
        const std::vector<BYTE>& credentialIdBytes,
        const std::wstring& rpId,
        const std::wstring& rpName,
        const std::vector<BYTE>& userHandle,
        const std::wstring& userName);
};
