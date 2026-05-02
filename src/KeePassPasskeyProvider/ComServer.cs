using System.Runtime.InteropServices;
using KeePassPasskeyShared;
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

        // Initial credential sync
        Log.Info("initial SyncToWindowsCache");
        CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

        // Capture main thread ID so the sync task can post WM_QUIT here to wake GetMessage.
        uint mainThreadId = Win32Native.GetCurrentThreadId();

        // Background sync thread
        using var cts = new CancellationTokenSource();
        var syncTask = Task.Run(() => SyncCredentialCacheLoop(cts.Token, mainThreadId));

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

    private static async Task SyncCredentialCacheLoop(CancellationToken token, uint mainThreadId)
    {
        int consecutiveFailures = 0;

        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(AppSettings.Current.CredentialSyncIntervalMilliseconds, token);
                Log.Info("periodic SyncToWindowsCache");
                bool reached = CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

                if (reached)
                {
                    consecutiveFailures = 0;
                }
                else
                {
                    consecutiveFailures++;
                    Log.Warn($"KeePass unreachable, failures={consecutiveFailures}/{AppSettings.Current.CredentialSyncShutdownThreshold}");
                    if (consecutiveFailures >= AppSettings.Current.CredentialSyncShutdownThreshold)
                    {
                        Log.Info("idle shutdown — KeePass unreachable for too long");
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
