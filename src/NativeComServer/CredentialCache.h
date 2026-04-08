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
};
