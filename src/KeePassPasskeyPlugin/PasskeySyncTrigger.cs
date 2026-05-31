// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassPasskey.Storage;
using KeePassPasskeyShared;

namespace KeePassPasskey
{
    /// <summary>
    /// Watches KeePass database events and triggers a one-shot provider credential-cache sync
    /// (KeePassPasskeyProvider.exe /synccredential) so passkeys appear in the Windows sign-in UI.
    /// The provider is the only process with the MSIX package identity required to write the
    /// Windows credential cache, so the plugin only detects change and launches it.
    /// </summary>
    internal sealed class PasskeySyncTrigger : IDisposable
    {
        // The provider's app execution alias forks by build identity so a dev plugin launches the
        // dev provider and a release plugin the release provider, even when both are installed.
#if DEBUG
        private const string ProviderAlias = "KeePassPasskeyProviderDev.exe";
#else
        private const string ProviderAlias = "KeePassPasskeyProvider.exe";
#endif
        private const int DebounceMs = 1000;

        private readonly IPluginHost _host;
        private readonly PasskeyEntryStorage _storage;
        private readonly SettingsStorage _settingsStorage;
        private readonly Timer _debounceTimer;
        private string _lastSignature = string.Empty;
        private bool _disposed;

        internal PasskeySyncTrigger(IPluginHost host, PasskeyEntryStorage storage, SettingsStorage settingsStorage)
        {
            _host = host;
            _storage = storage;
            _settingsStorage = settingsStorage;

            _debounceTimer = new Timer { Interval = DebounceMs };
            _debounceTimer.Tick += OnDebounceTick;

            _host.MainWindow.FileOpened      += OnForcedSyncEvent;
            _host.MainWindow.FileSaved       += OnForcedSyncEvent;
            _host.MainWindow.FileClosingPost += OnForcedSyncEvent;
            _host.MainWindow.UIStateUpdated  += OnUIStateUpdated;

            // A database may already be open (KeePass auto-open on startup, or the plugin loaded
            // after the database was opened).
            if (IsAnyDatabaseOpen())
                ScheduleSync();
        }

        // FileOpened / FileSaved / FileClosingPost are EventHandler<T>; method-group contravariance
        // lets a single (object, EventArgs) handler bind to all three. These are forced syncs
        // (they bypass the signature gate) because the open-database set changed.
        private void OnForcedSyncEvent(object sender, EventArgs e) => ScheduleSync();

        private void OnUIStateUpdated(object sender, EventArgs e)
        {
            // Only react when the passkey set actually changed; UIStateUpdated also fires on benign
            // UI activity (selection, focus, refresh).
            if (ComputeSignatureSafe() == _lastSignature) return;
            ScheduleSync();
        }

        private void ScheduleSync()
        {
            if (_disposed) return;
            _debounceTimer.Stop();
            _debounceTimer.Start();
        }

        private void OnDebounceTick(object sender, EventArgs e)
        {
            _debounceTimer.Stop();
            try
            {
                if (!_settingsStorage.Load().IsCredentialSyncEnabled)
                {
                    Log.Debug("credential sync disabled, skipping trigger");
                    return;
                }

                _lastSignature = ComputeSignatureSafe();
                Task.Run((Action)LaunchProviderSync);
            }
            catch (Exception ex)
            {
                Log.Warn("sync trigger error: " + ex.Message);
            }
        }

        private string ComputeSignatureSafe()
        {
            try { return _storage.ComputePasskeySignature(); }
            catch (Exception ex)
            {
                Log.Warn("signature computation failed: " + ex.Message);
                return _lastSignature; // treat as unchanged so an error never spams syncs
            }
        }

        private void LaunchProviderSync()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName        = ProviderAlias,
                    Arguments       = "/synccredential",
                    UseShellExecute = false,
                    CreateNoWindow  = true,
                });
                Log.Debug("launched " + ProviderAlias + " /synccredential");
            }
            catch (Exception ex)
            {
                Log.Warn("failed to launch provider sync (" + ProviderAlias + "): " + ex.Message);
            }
        }

        private bool IsAnyDatabaseOpen()
        {
            foreach (var doc in _host.MainWindow.DocumentManager.Documents)
                if (doc.Database != null && doc.Database.IsOpen) return true;
            return _host.Database != null && _host.Database.IsOpen;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _host.MainWindow.FileOpened      -= OnForcedSyncEvent;
            _host.MainWindow.FileSaved       -= OnForcedSyncEvent;
            _host.MainWindow.FileClosingPost -= OnForcedSyncEvent;
            _host.MainWindow.UIStateUpdated  -= OnUIStateUpdated;

            _debounceTimer.Stop();
            _debounceTimer.Tick -= OnDebounceTick;
            _debounceTimer.Dispose();
        }
    }
}
