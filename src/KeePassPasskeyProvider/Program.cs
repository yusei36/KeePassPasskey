// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.App;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

/// <summary>
/// Entry point for the managed passkey COM server.
/// Handles both -ActivateAuthenticator (COM server mode)
/// and /register | /unregister | /status (management mode).
/// </summary>
internal static class Program
{
    [MTAThread]
    static int Main(string[] args)
    {
        KeePassPasskeySettings.Current = SettingsCache.TryLoad() ?? new KeePassPasskeySettings();
        AppSettings.Current  = AppSettings.TryLoad() ?? new AppSettings();

        Log.Configure(
            Path.Combine(SettingsCache.SettingsDir, "Provider.log"),
            KeePassPasskeySettings.Current.LogLevel);

        if (IsToastActivation())
            return 0;

        bool activateAuthenticator = args.Any(a =>
            string.Equals(a, "-ActivateAuthenticator", StringComparison.OrdinalIgnoreCase));

        if (activateAuthenticator)
        {
            Log.Info($"-ActivateAuthenticator received (log level: {Log.MinLevel})");
            return ComServer.RunComServer();
        }

        // No args: show management UI
        if (args.Length == 0)
            return RunManagementUI();

        // /register | /unregister | /status - attach to parent console so output is visible
        Win32Native.AttachConsole(Win32Native.ATTACH_PARENT_PROCESS);

        return RunManagementCommand(args);
    }

    private static bool IsToastActivation()
    {
        try
        {
            return AppInstance.GetActivatedEventArgs()?.Kind == ActivationKind.ToastNotification;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Management UI mode (no args). Shows an Avalonia window on a dedicated STA thread.
    /// Uses a mutex to ensure only one UI instance runs.
    /// </summary>
    private static int RunManagementUI()
    {
        const string MutexName = "Local\\KeePassPasskeyProvider_UI";
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
            Log.Info($"First instance; starting UI (log level: {Log.MinLevel})");
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
            .FirstOrDefault(p => p.Id != Environment.ProcessId);

        if (existing == null)
        {
            Log.Warn("Could not find existing process");
            return;
        }

        nint hwnd = existing.MainWindowHandle;
        if (hwnd != 0)
        {
            Win32Native.ShowWindow(hwnd, Win32Native.SW_RESTORE);
            Win32Native.SetForegroundWindow(hwnd);
            Log.Info($"Activated window 0x{hwnd:X}");
            return;
        }

        // Window is hidden to tray — signal the running instance to show itself
        nint ev = Win32Native.OpenEvent(Win32Native.EVENT_MODIFY_STATE, false, TrayIconService.ShowEventName);
        if (ev != 0)
        {
            Win32Native.SetEvent(ev);
            Win32Native.CloseHandle(ev);
            Log.Info("Signalled running instance to show window");
        }
        else
        {
            Log.Warn("Could not find existing window or show-window event");
        }
    }

    private static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<Application>()
            .UsePlatformDetect()
            .LogToTrace();

    /// <summary>
    /// Management command mode (/register, /unregister, /status).
    /// Handles COM registration, unregistration, and status queries.
    /// </summary>
    private static int RunManagementCommand(string[] args)
    {
        string cmd = args.Length > 1 ? args[1] : (args.Length > 0 ? args[0] : string.Empty);

        switch (cmd.ToLowerInvariant())
        {
            case "/register":
            {
                int hr = PluginRegistration.Register();
                if (hr >= HResults.S_OK)
                    Console.WriteLine("KeePassPasskey Provider registered successfully.");
                else
                    Console.WriteLine($"Registration failed: 0x{hr:X8}");
                return hr >= HResults.S_OK ? 0 : 1;
            }

            case "/unregister":
            {
                int hr = PluginRegistration.Unregister();
                if (hr >= HResults.S_OK)
                    Console.WriteLine("KeePassPasskey Provider unregistered.");
                else
                    Console.WriteLine($"Unregister failed: 0x{hr:X8}");
                return hr >= HResults.S_OK ? 0 : 1;
            }

            case "/status":
            {
                int hr = PluginRegistration.GetState(out var state);
                if (hr >= HResults.S_OK)
                {
                    string stateStr = state == AuthenticatorState.AuthenticatorState_Enabled
                        ? "Enabled" : "Disabled";
                    Console.WriteLine($"Plugin state: {stateStr}");
                }
                else
                {
                    Console.WriteLine($"GetPluginState failed: 0x{hr:X8}");
                }
                return hr >= HResults.S_OK ? 0 : 1;
            }

            default:
                Console.WriteLine("KeePassPasskey Provider");
                Console.WriteLine("Usage: KeePassPasskeyProvider.exe /register | /unregister | /status");
                return 0;
        }
    }
}
