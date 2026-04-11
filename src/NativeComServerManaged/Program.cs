using System.Runtime.InteropServices;
using PasskeyProviderManaged.Interop;
using PasskeyProviderManaged.Plugin;
using PasskeyProviderManaged.Util;

namespace PasskeyProviderManaged;

/// <summary>
/// Entry point for the managed passkey COM server.
/// Mirrors main.cpp — handles both -PluginActivated (COM server mode)
/// and /register | /unregister | /status (management mode).
/// </summary>
internal static class Program
{
    private const int SyncIntervalMs = 30_000;

    [MTAThread] // .NET initializes COM as MTA before Main runs; explicit CoInitializeEx calls return S_FALSE (already initialized)
    static int Main(string[] args)
    {
        bool isPluginActivated = args.Any(a =>
            string.Equals(a, "-PluginActivated", StringComparison.OrdinalIgnoreCase));

        if (isPluginActivated)
        {
            Log.Write("Main: -PluginActivated received");
            return RunAsPluginServer();
        }

        // Management UI path — attach to parent console so output is visible
        Win32Native.AttachConsole(Win32Native.ATTACH_PARENT_PROCESS);

        int hr = Win32Native.CoInitializeEx(0, Win32Native.COINIT_MULTITHREADED);
        if (hr < 0)
        {
            Console.WriteLine($"CoInitializeEx failed: 0x{hr:X8}");
            return 1;
        }

        try
        {
            return RunManagementCommand(args);
        }
        finally
        {
            Win32Native.CoUninitialize();
        }
    }

    // -----------------------------------------------------------------
    // COM server mode (-PluginActivated)
    // -----------------------------------------------------------------

    private static int RunAsPluginServer()
    {
        int hr = Win32Native.CoInitializeEx(0, Win32Native.COINIT_MULTITHREADED);
        Log.Write($"RunAsPluginServer: CoInitializeEx hr=0x{hr:X8}");
        if (hr < 0) return hr;

        try
        {
            var factory = new ClassFactory();
            uint cookie;
            try
            {
                cookie = ComRegistration.RegisterClassFactory(factory);
            }
            catch (Exception ex)
            {
                Log.Write($"RunAsPluginServer: RegisterClassFactory failed: {ex.Message}");
                return Marshal.GetHRForException(ex);
            }
            Log.Write($"RunAsPluginServer: registered class factory cookie={cookie}");

            // Initial credential sync
            Log.Write("RunAsPluginServer: initial SyncToWindowsCache");
            CredentialCache.SyncToWindowsCache(PluginConstants.KeePassClsid);

            // Background sync thread
            using var cts = new CancellationTokenSource();
            var syncTask = Task.Run(() => SyncLoop(cts.Token));

            // Win32 message loop
            Log.Write("RunAsPluginServer: entering message loop");
            Win32Native.MSG msg;
            while (Win32Native.GetMessage(out msg, 0, 0, 0) > 0)
            {
                Win32Native.TranslateMessage(in msg);
                Win32Native.DispatchMessage(in msg);
            }
            Log.Write("RunAsPluginServer: message loop exited");

            cts.Cancel();
            syncTask.Wait(5000);

            ComRegistration.RevokeClassFactory(cookie);
        }
        finally
        {
            Win32Native.CoUninitialize();
        }

        Log.Write("RunAsPluginServer: exiting");
        return 0;
    }

    private static async Task SyncLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SyncIntervalMs, token);
                Log.Write("SyncThread: periodic SyncToWindowsCache");
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassClsid);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Write($"SyncThread: exception {ex.Message}");
            }
        }
        Log.Write("SyncThread: exiting");
    }

    // -----------------------------------------------------------------
    // Management command mode (/register, /unregister, /status)
    // -----------------------------------------------------------------

    private static int RunManagementCommand(string[] args)
    {
        string cmd = args.Length > 1 ? args[1] : (args.Length > 0 ? args[0] : string.Empty);

        switch (cmd.ToLowerInvariant())
        {
            case "/register":
            {
                int hr = PluginRegistration.Register();
                if (hr >= 0)
                    Console.WriteLine("KeePass Passkey Provider registered successfully.");
                else
                    Console.WriteLine($"Registration failed: 0x{hr:X8}");
                return hr >= 0 ? 0 : 1;
            }

            case "/unregister":
            {
                int hr = PluginRegistration.Unregister();
                if (hr >= 0)
                    Console.WriteLine("KeePass Passkey Provider unregistered.");
                else
                    Console.WriteLine($"Unregister failed: 0x{hr:X8}");
                return hr >= 0 ? 0 : 1;
            }

            case "/status":
            {
                int hr = PluginRegistration.GetState(out var state);
                if (hr >= 0)
                {
                    string stateStr = state == AuthenticatorState.AuthenticatorState_Enabled
                        ? "Enabled" : "Disabled";
                    Console.WriteLine($"Plugin state: {stateStr}");
                }
                else
                {
                    Console.WriteLine($"GetPluginState failed: 0x{hr:X8}");
                }
                return hr >= 0 ? 0 : 1;
            }

            default:
                Console.WriteLine("KeePass Passkey Provider (managed)");
                Console.WriteLine("Usage: PasskeyProviderManaged.exe /register | /unregister | /status");
                return 0;
        }
    }
}
