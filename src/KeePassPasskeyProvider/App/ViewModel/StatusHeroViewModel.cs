// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class StatusHeroViewModel : ObservableObject
{
    [ObservableProperty] public partial ProviderStatus Status { get; set; }
    [ObservableProperty] public partial string Subhead { get; set; } = "";
    [ObservableProperty] public partial PluginPillState PluginStatus { get; set; }
    [ObservableProperty] public partial bool CanRegister { get; set; } = true;
    [ObservableProperty] public partial bool CanUnregister { get; set; }
    [ObservableProperty] public partial bool ShowOpenPasskeySettings { get; set; }
    [ObservableProperty] public partial bool ShowPluginFile { get; set; }

    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }
    public ICommand RefreshCommand    { get; }
    public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;
    public ICommand ShowPluginFileCommand => ProviderCommands.ShowPluginFileCommand;

    internal StatusHeroViewModel(ICommand register, ICommand unregister, ICommand refresh)
    {
        RegisterCommand   = register;
        UnregisterCommand = unregister;
        RefreshCommand    = refresh;
    }

    internal void Update(
        bool pluginRunning,
        bool providerEnabled,
        bool isRegistered,
        bool autoregisterError,
        PingStatus pingStatus,
        string? pluginVersion)
    {
        PluginStatus = pingStatus switch
        {
            PingStatus.IncompatibleVersion => PluginPillState.IncompatibleVersion,
            PingStatus.NoDatabase          => PluginPillState.NoDatabase,
            PingStatus.Ready => DiagnosticsViewModel.ProductVersionsDiffer(pluginVersion)
                ? PluginPillState.VersionMismatch
                : PluginPillState.Running,
            _ => PluginPillState.NotConnected,
        };
        CanRegister             = !isRegistered;
        CanUnregister           = isRegistered;
        ShowOpenPasskeySettings = isRegistered && !providerEnabled && !autoregisterError;

        Status = (autoregisterError, isRegistered, providerEnabled, pluginRunning, pingStatus) switch
        {
            (true,  _,     _,     _,     _)                          => ProviderStatus.AutoregisterFailed,
            (_,     false, _,     _,     _)                          => ProviderStatus.NotRegistered,
            (_,     _,     false, _,     _)                          => ProviderStatus.WaitingToBeEnabled,
            (_,     _,     _,     _,     PingStatus.IncompatibleVersion) => ProviderStatus.IncompatibleVersion,
            (_,     _,     _,     _,     PingStatus.NoDatabase)      => ProviderStatus.NoDatabase,
            (_,     _,     _,     false, _)                          => ProviderStatus.KeePassNotConnected,
            _ => DiagnosticsViewModel.ProductVersionsDiffer(pluginVersion)
                ? ProviderStatus.VersionMismatch
                : ProviderStatus.Ready,
        };

        Subhead = Status switch
        {
            ProviderStatus.AutoregisterFailed => "You can retry by clicking Register.",
            ProviderStatus.NotRegistered      => "Click Register to set up KeePassPasskey as your passkey provider.",
            ProviderStatus.WaitingToBeEnabled => "Click Advanced Passkey Options below to enable KeePassPasskey.",
            ProviderStatus.IncompatibleVersion => Notifier.VersionMismatchBody(DiagnosticsViewModel.ClientVersion, pluginVersion),
            ProviderStatus.VersionMismatch    => DiagnosticsViewModel.VersionDifferenceMessage(pluginVersion),
            ProviderStatus.NoDatabase         => "Open a KeePass database to use passkeys.",
            ProviderStatus.KeePassNotConnected => "Start KeePass with the KeePassPasskey plugin installed.",
            _                                  => "Provider is enabled and the KeePass plugin is running.",
        };

        // On a version difference the bundled plugin only helps when the plugin is the older side.
        ShowPluginFile = ProviderCommands.HasBundledPlugin
            && (Status == ProviderStatus.KeePassNotConnected
                || (Status is ProviderStatus.IncompatibleVersion or ProviderStatus.VersionMismatch
                    && PipeConstants.CompareProductVersions(DiagnosticsViewModel.ClientVersion, pluginVersion) > 0));
    }
}
