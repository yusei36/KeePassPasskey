using System.Runtime.InteropServices;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Plugin;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

/// <summary>
/// Entry point for the managed passkey COM server.
/// Mirrors main.cpp — handles both -PluginActivated (COM server mode)
/// and /register | /unregister | /status (management mode).
/// </summary>
internal static class Program
{
    private const int SyncIntervalMs = 30_000;

    [MTAThread]
    static int Main(string[] args)
    {
        bool isPluginActivated = args.Any(a =>
            string.Equals(a, "-PluginActivated", StringComparison.OrdinalIgnoreCase));

        if (isPluginActivated)
        {
            Log.Info("-PluginActivated received");
            return RunAsPluginServer();
        }

        // Management UI path — attach to parent console so output is visible
        Win32Native.AttachConsole(Win32Native.ATTACH_PARENT_PROCESS);

        return RunManagementCommand(args);
    }

    // -----------------------------------------------------------------
    // COM server mode (-PluginActivated) -- must initialized as MTA by [MTAThread]
    // -----------------------------------------------------------------

    private static int RunAsPluginServer()
    {
        var factory = new ClassFactory();
        uint cookie;
        try
        {
            cookie = ComRegistration.RegisterClassFactory(factory);
        }
        catch (Exception ex)
        {
            Log.Error($"RegisterClassFactory failed: {ex.Message}");
            return Marshal.GetHRForException(ex);
        }
        Log.Info($"registered class factory cookie={cookie}");

        // Initial credential sync
        Log.Info("initial SyncToWindowsCache");
        CredentialCache.SyncToWindowsCache(PluginConstants.KeePassClsid);

        // Background sync thread
        using var cts = new CancellationTokenSource();
        var syncTask = Task.Run(() => SyncLoop(cts.Token));

        // Win32 message loop
        Log.Info("entering message loop");
        Win32Native.MSG msg;
        while (Win32Native.GetMessage(out msg, 0, 0, 0) > 0)
        {
            Win32Native.TranslateMessage(in msg);
            Win32Native.DispatchMessage(in msg);
        }
        Log.Info("message loop exited");

        cts.Cancel();
        syncTask.Wait(5000);

        ComRegistration.RevokeClassFactory(cookie);
        Log.Info("exiting");
        return 0;
    }

    private static async Task SyncLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SyncIntervalMs, token);
                Log.Info("periodic SyncToWindowsCache");
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassClsid);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Error($"exception {ex.Message}");
            }
        }
        Log.Info("exiting");
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
                Console.WriteLine("Usage: KeePassPasskeyProvider.exe /register | /unregister | /status");
                return 0;
        }
    }
}
