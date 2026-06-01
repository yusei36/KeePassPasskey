// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

internal static class ComServer
{
    // The COM server is purely on-demand: Windows cold-starts it per operation and it self-exits
    // when idle. Cache population is the plugin's job (/synccredential), not the server's.
    private static readonly TimeSpan IdleTimeout       = TimeSpan.FromSeconds(150);
    private static readonly TimeSpan IdleCheckInterval = TimeSpan.FromSeconds(30);

    internal static int RunComServer()
    {
        using var mutex = new Mutex(false, PluginConstants.ComServerMutexName);
        if (!mutex.WaitOne(0))
        {
            Log.Warn("COM server already running, exiting");
            return 0;
        }

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

        PluginRegistration.EnsureRegistered();

        // Capture main thread ID so the idle timer can post WM_QUIT here to wake GetMessage.
        uint mainThreadId = Win32Native.GetCurrentThreadId();

        // Pick up settings changes (the management app writes the cache file on save).
        Directory.CreateDirectory(AppPaths.SettingsDir);
        using var settingsFileWatcher = new FileSystemWatcher(AppPaths.SettingsDir)
        {
            Filter              = SettingsCache.SettingsFileName,
            NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.FileName,
            EnableRaisingEvents = true,
        };
        void ReloadSettings(object? _, FileSystemEventArgs __)
        {
            var updatedSettings = SettingsCache.TryLoad();
            if (updatedSettings != null)
                KeePassPasskeySettings.Current = updatedSettings;
        }
        settingsFileWatcher.Changed += ReloadSettings;
        settingsFileWatcher.Created += ReloadSettings;
        settingsFileWatcher.Renamed += (s, e) => ReloadSettings(s, e);

        // Quit once idle (see ComActivity), waking the message loop via WM_QUIT.
        using var idleTimer = new System.Threading.Timer(_ =>
        {
            if (ComActivity.IsIdle(IdleTimeout))
            {
                Log.Info("idle timeout reached, requesting shutdown");
                Win32Native.PostThreadMessage(mainThreadId, Win32Native.WM_QUIT, 0, 0);
            }
        }, null, IdleCheckInterval, IdleCheckInterval);

        // Win32 message loop
        Log.Info("entering message loop");
        Win32Native.MSG msg;
        while (Win32Native.GetMessage(out msg, 0, 0, 0) > 0)
        {
            Win32Native.TranslateMessage(in msg);
            Win32Native.DispatchMessage(in msg);
        }
        Log.Info("message loop exited");

        ComRegistration.RevokeClassFactory(cookie);
        Log.Info("exiting");
        return 0;
    }
}
