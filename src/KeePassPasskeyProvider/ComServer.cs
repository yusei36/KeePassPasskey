using System.Runtime.InteropServices;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Config;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

internal static class ComServer
{
    internal static int RunComServer()
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

        PluginRegistration.EnsureRegistered();

        // Initial config + credential sync
        Log.Info("initial SyncConfig");
        SyncConfig();
        Log.Info("initial SyncToWindowsCache");
        CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

        // Capture main thread ID so the sync task can post WM_QUIT here to wake GetMessage.
        uint mainThreadId = Win32Native.GetCurrentThreadId();

        // Background sync thread
        using var cts = new CancellationTokenSource();
        var syncTask = Task.Run(() => SyncLoop(cts.Token, mainThreadId));

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

    private static bool SyncConfig()
    {
        var configResponse = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient))).GetConfig();
        if (configResponse == null)
        {
            Log.Info("KeePass unavailable or error, skipping config sync");
            return false;
        }
        if (configResponse.ErrorCode != null)
        {
            Log.Warn($"GetConfig returned error={configResponse.ErrorCode} errorMessage={configResponse.ErrorMessage}, skipping config sync");
            return false;
        }

        if (!configResponse.Config.Equals(KeePassPasskeyConfig.Current))
        {
            KeePassPasskeyConfig.Current = configResponse.Config;
            ConfigPersistence.Save(configResponse.Config);
        }

        return true;
    }

    private static async Task SyncLoop(CancellationToken token, uint mainThreadId)
    {
        int consecutiveFailures = 0;
        var lastConfigSync     = DateTime.UtcNow;
        var lastCredentialSync = DateTime.UtcNow;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var cfg = KeePassPasskeyConfig.Current;
                bool configSyncEnabled     = cfg.ConfigSyncIntervalMilliseconds > 0;
                bool credentialSyncEnabled = cfg.CredentialSyncIntervalMilliseconds > 0;

                if (!configSyncEnabled && !credentialSyncEnabled)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), token);
                    continue;
                }

                var nextConfigSync     = configSyncEnabled
                    ? lastConfigSync     + TimeSpan.FromMilliseconds(cfg.ConfigSyncIntervalMilliseconds)
                    : DateTime.MaxValue;
                var nextCredentialSync = credentialSyncEnabled
                    ? lastCredentialSync + TimeSpan.FromMilliseconds(cfg.CredentialSyncIntervalMilliseconds)
                    : DateTime.MaxValue;

                var delay = (nextConfigSync < nextCredentialSync ? nextConfigSync : nextCredentialSync) - DateTime.UtcNow;
                if (delay > TimeSpan.Zero)
                    await Task.Delay(delay, token);

                var now = DateTime.UtcNow;

                if (configSyncEnabled && now >= nextConfigSync)
                {
                    SyncConfig();
                    lastConfigSync = now;
                }

                if (credentialSyncEnabled && now >= nextCredentialSync)
                {
                    bool credentialSyncSuccessful = CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
                    lastCredentialSync = now;

                    if (credentialSyncSuccessful)
                    {
                        consecutiveFailures = 0;
                    }
                    else
                    {
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
