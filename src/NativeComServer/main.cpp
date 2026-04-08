#include "pch.h"
#include "PluginAuthenticator.h"
#include "PluginRegistration.h"
#include "CredentialCache.h"
#include <wrl/module.h>
#include <string>
#include <cstdio>

static void LogMain(const char* fmt, ...)
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

using namespace Microsoft::WRL;

static constexpr DWORD SYNC_INTERVAL_MS = 30 * 1000; // sync every 30 seconds

static HANDLE g_hStopSync = nullptr;

static DWORD WINAPI SyncThreadProc(LPVOID)
{
    while (WaitForSingleObject(g_hStopSync, SYNC_INTERVAL_MS) == WAIT_TIMEOUT)
    {
        LogMain("SyncThread: periodic SyncToWindowsCache");
        CredentialCache::SyncToWindowsCache(KEEPASS_PASSKEY_PLUGIN_CLSID);
    }
    LogMain("SyncThread: exiting");
    return 0;
}

// Called by the Windows passkey platform when a passkey operation is needed.
// Registers the COM class factory and keeps running, periodically syncing credentials.
static HRESULT RunAsPluginServer()
{
    LogMain("RunAsPluginServer: entry");
    DWORD dwCookie = 0;
    auto factory = Make<PluginAuthenticatorFactory>();
    if (!factory) return E_OUTOFMEMORY;

    HRESULT hrReg = CoRegisterClassObject(
        KEEPASS_PASSKEY_PLUGIN_CLSID,
        factory.Get(),
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &dwCookie);
    LogMain("RunAsPluginServer: CoRegisterClassObject hr=0x%08X cookie=%u", hrReg, dwCookie);
    RETURN_IF_FAILED(hrReg);

    // Sync credentials to the Windows autofill cache on startup
    LogMain("RunAsPluginServer: calling SyncToWindowsCache");
    HRESULT hrSync = CredentialCache::SyncToWindowsCache(KEEPASS_PASSKEY_PLUGIN_CLSID);
    LogMain("RunAsPluginServer: SyncToWindowsCache hr=0x%08X", hrSync);

    // Start background thread for periodic sync
    g_hStopSync = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE hSyncThread = g_hStopSync
        ? CreateThread(nullptr, 0, SyncThreadProc, nullptr, 0, nullptr)
        : nullptr;
    LogMain("RunAsPluginServer: sync thread started=%s", hSyncThread ? "yes" : "no");

    // Run the COM message loop
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Stop the sync thread
    if (g_hStopSync) SetEvent(g_hStopSync);
    if (hSyncThread)
    {
        WaitForSingleObject(hSyncThread, 5000);
        CloseHandle(hSyncThread);
    }
    if (g_hStopSync) { CloseHandle(g_hStopSync); g_hStopSync = nullptr; }

    CoRevokeClassObject(dwCookie);
    return S_OK;
}

// Simple management UI — runs when the user launches the EXE directly.
static void RunManagementUI(int argc, wchar_t* argv[])
{
    // Attach to the parent console (e.g. PowerShell) so wprintf output is visible.
    // GUI subsystem EXEs don't inherit a console automatically.
    // After AttachConsole, re-open stdout/stderr to CONOUT$ so the C runtime
    // actually routes wprintf to the newly attached console (the handles it
    // inherited at process start still point to NUL for a GUI subsystem EXE).
    AttachConsole(ATTACH_PARENT_PROCESS);
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);

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
        LogMain("wWinMain: -PluginActivated, calling CoInitializeEx");
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        LogMain("wWinMain: CoInitializeEx hr=0x%08X", hr);
        if (SUCCEEDED(hr))
        {
            RunAsPluginServer();
            CoUninitialize();
        }
        LocalFree(argv);
        LogMain("wWinMain: exiting");
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
