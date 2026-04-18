using System.Runtime.InteropServices;
using System.Threading;
using Avalonia;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Plugin;
using KeePassPasskeyProvider.UI;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

/// <summary>
/// Entry point for the managed passkey COM server.
/// Handles both -PluginActivated (COM server mode)
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

        // No args: show management UI
        if (args.Length == 0)
            return RunManagementUI();

        // /register | /unregister | /status — attach to parent console so output is visible
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
        CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

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
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
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
    // Management UI mode (no args) -- Avalonia window on a dedicated STA thread
    // -----------------------------------------------------------------

    private static int RunManagementUI()
    {
        const string MutexName = "Global\\KeePassPasskeyProvider_UI";
        var mutex = new Mutex(false, MutexName);

        try
        {
            if (!mutex.WaitOne(0))
            {
                // Another instance is running; activate its window and exit
                Log.Info("Another instance is already running; activating existing window");
                ActivateExistingWindow();
                return 0;
            }

            // Mutex acquired; we are the first instance
            Log.Info("First instance; starting UI");
            int exitCode = 0;
            var uiThread = new Thread(() =>
            {
                exitCode = BuildAvaloniaApp()
                    .StartWithClassicDesktopLifetime([]);
            });
            uiThread.SetApartmentState(ApartmentState.STA);
            uiThread.Start();
            uiThread.Join();
            return exitCode;
        }
        finally
        {
            mutex?.Dispose();
        }
    }

    private static void ActivateExistingWindow()
    {
        var existing = System.Diagnostics.Process.GetProcessesByName("KeePassPasskeyProvider")
            .FirstOrDefault(p => p.Id != Environment.ProcessId && p.MainWindowHandle != 0);

        nint hwnd = existing?.MainWindowHandle ?? 0;
        if (hwnd != 0)
        {
            Win32Native.ShowWindow(hwnd, Win32Native.SW_RESTORE);
            Win32Native.SetForegroundWindow(hwnd);
            Log.Info($"Activated window 0x{hwnd:X}");
        }
        else
        {
            Log.Warn("Could not find existing window");
        }
    }

    private static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .LogToTrace();

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
                    Console.WriteLine("KeePassPasskey Provider registered successfully.");
                else
                    Console.WriteLine($"Registration failed: 0x{hr:X8}");
                return hr >= 0 ? 0 : 1;
            }

            case "/unregister":
            {
                int hr = PluginRegistration.Unregister();
                if (hr >= 0)
                    Console.WriteLine("KeePassPasskey Provider unregistered.");
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
                Console.WriteLine("KeePassPasskey Provider");
                Console.WriteLine("Usage: KeePassPasskeyProvider.exe /register | /unregister | /status");
                return 0;
        }
    }
}
