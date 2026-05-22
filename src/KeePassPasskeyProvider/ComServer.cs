// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

internal static class ComServer
{
    internal static int RunComServer()
    {
        const string MutexName = "Local\\KeePassPasskeyProvider_COM";
        using var mutex = new Mutex(false, MutexName);
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

        Log.Info("initial SyncSettings");
        bool keepassReachable = SyncSettings();
        Log.Info("initial SyncToWindowsCache");
        CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

        // Capture main thread ID so the sync task can post WM_QUIT here to wake GetMessage.
        uint mainThreadId = Win32Native.GetCurrentThreadId();

        // Watch cached settings file â€” reloads KeePassPasskeySettings.Current whenever the file is written.
        Directory.CreateDirectory(AppPaths.SettingsDir);
        using var settingsFileWatcher = new FileSystemWatcher(AppPaths.SettingsDir)
        {
            Filter              = SettingsCache.SettingsFileName,
            NotifyFilter        = NotifyFilters.LastWrite,
            EnableRaisingEvents = true,
        };
        settingsFileWatcher.Changed += (_, _) =>
        {
            var updatedSettings = SettingsCache.TryLoad();
            if (updatedSettings != null)
                KeePassPasskeySettings.Current = updatedSettings;
        };

        // Background sync thread
        using var cts = new CancellationTokenSource();
        var syncTask = Task.Run(() => SyncLoop(cts.Token, mainThreadId, keepassReachable));

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

    private static bool SyncSettings()
    {
        var settingsResponse = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient))).GetSettings();
        if (settingsResponse == null)
        {
            Log.Info("KeePass unavailable or error, skipping settings sync");
            return false;
        }
        if (settingsResponse.ErrorCode != null)
        {
            Log.Warn($"GetSettings returned error={settingsResponse.ErrorCode} errorMessage={settingsResponse.ErrorMessage}, skipping settings sync");
            return false;
        }

        if (!settingsResponse.Settings.Equals(KeePassPasskeySettings.Current))
        {
            KeePassPasskeySettings.Current = settingsResponse.Settings;
            SettingsCache.Save(settingsResponse.Settings);
        }

        return true;
    }

    private static async Task SyncLoop(CancellationToken token, uint mainThreadId, bool wasReachable)
    {
        int consecutiveFailures = 0;
        var lastCredentialSync  = DateTime.UtcNow;
        bool syncWasEnabled     = KeePassPasskeySettings.Current.IsCredentialSyncEnabled;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var cfg         = KeePassPasskeySettings.Current;
                bool syncEnabled = cfg.IsCredentialSyncEnabled;

                if (!syncEnabled)
                {
                    if (syncWasEnabled)
                    {
                        CredentialCache.ClearWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
                        syncWasEnabled = false;
                    }
                    await Task.Delay(TimeSpan.FromSeconds(5), token);
                    continue;
                }

                syncWasEnabled = true;

                var delay = lastCredentialSync
                    + TimeSpan.FromMilliseconds(cfg.CredentialSyncIntervalMilliseconds)
                    - DateTime.UtcNow;
                if (delay > TimeSpan.Zero)
                    await Task.Delay(delay, token);

                bool ok = CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
                lastCredentialSync = DateTime.UtcNow;

                if (ok)
                {
                    consecutiveFailures = 0;
                    if (!wasReachable)
                    {
                        wasReachable = true;
                        SyncSettings();
                    }
                }
                else
                {
                    wasReachable = false;
                    consecutiveFailures++;
                    Log.Warn($"KeePass unreachable, failures={consecutiveFailures}/{cfg.CredentialSyncShutdownThreshold}");
                    if (consecutiveFailures >= cfg.CredentialSyncShutdownThreshold)
                    {
                        Log.Info("idle shutdown - KeePass unreachable for too long");
                        Win32Native.PostThreadMessage(mainThreadId, Win32Native.WM_QUIT, 0, 0);
                        break;
                    }
                }
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
}
