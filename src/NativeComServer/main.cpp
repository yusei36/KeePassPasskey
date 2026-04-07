#include "pch.h"
#include "PluginAuthenticator.h"
#include "PluginRegistration.h"
#include "CredentialCache.h"
#include <wrl/module.h>
#include <string>
#include <cstdio>

using namespace Microsoft::WRL;

// Called by the Windows passkey platform when a passkey operation is needed.
// Registers the COM class factory and waits until the platform is done.
static HRESULT RunAsPluginServer()
{
    DWORD dwCookie = 0;
    auto factory = Make<PluginAuthenticatorFactory>();
    if (!factory) return E_OUTOFMEMORY;

    RETURN_IF_FAILED(CoRegisterClassObject(
        KEEPASS_PASSKEY_PLUGIN_CLSID,
        factory.Get(),
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &dwCookie));

    // Sync credentials to the Windows autofill cache on startup
    CredentialCache::SyncToWindowsCache(KEEPASS_PASSKEY_PLUGIN_CLSID);

    // Run the message loop — exit when all COM instances are released
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoRevokeClassObject(dwCookie);
    return S_OK;
}

// Simple management UI — runs when the user launches the EXE directly.
static void RunManagementUI(int argc, wchar_t* argv[])
{
    // Parse command: /register, /unregister, /status
    std::wstring cmd = (argc > 1) ? argv[1] : L"";

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        wprintf(L"CoInitializeEx failed: 0x%08X\n", hr);
        return;
    }

    if (cmd == L"/register")
    {
        hr = RegisterPlugin();
        if (SUCCEEDED(hr))
            wprintf(L"KeePass Passkey Provider registered successfully.\n");
        else
            wprintf(L"Registration failed: 0x%08X\n", hr);
    }
    else if (cmd == L"/unregister")
    {
        hr = UnregisterPlugin();
        if (SUCCEEDED(hr))
            wprintf(L"KeePass Passkey Provider unregistered.\n");
        else
            wprintf(L"Unregister failed: 0x%08X\n", hr);
    }
    else if (cmd == L"/status")
    {
        AUTHENTICATOR_STATE state;
        hr = GetPluginState(state);
        if (SUCCEEDED(hr))
        {
            wprintf(L"Plugin state: %s\n",
                state == AuthenticatorState_Enabled ? L"Enabled" :
                state == AuthenticatorState_Disabled ? L"Disabled" : L"Unknown");
        }
        else
            wprintf(L"GetPluginState failed: 0x%08X\n", hr);
    }
    else
    {
        wprintf(L"KeePass Passkey Provider\n");
        wprintf(L"Usage: PasskeyProvider.exe /register | /unregister | /status\n");
    }

    CoUninitialize();
}

int WINAPI wWinMain(
    _In_     HINSTANCE /*hInstance*/,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_     LPWSTR    lpCmdLine,
    _In_     int       /*nCmdShow*/)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(lpCmdLine, &argc);
    // argv[0] is first actual argument when using CommandLineToArgvW on lpCmdLine

    // Check for -PluginActivated (sent by the Windows passkey platform)
    bool isPluginActivated = false;
    for (int i = 0; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"-PluginActivated") == 0)
        {
            isPluginActivated = true;
            break;
        }
    }

    if (isPluginActivated)
    {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr))
        {
            RunAsPluginServer();
            CoUninitialize();
        }
        LocalFree(argv);
        return 0;
    }

    // Management UI path — re-parse with full argv including exe name
    LocalFree(argv);

    int fullArgc = 0;
    LPWSTR* fullArgv = CommandLineToArgvW(GetCommandLineW(), &fullArgc);
    RunManagementUI(fullArgc, fullArgv);
    LocalFree(fullArgv);
    return 0;
}
