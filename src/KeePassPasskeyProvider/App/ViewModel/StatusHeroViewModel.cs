// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class StatusHeroViewModel : ObservableObject
{
    [ObservableProperty] public partial ProviderStatus Status { get; set; }
    [ObservableProperty] public partial PingStatus PluginStatus { get; set; }
    [ObservableProperty] public partial bool CanRegister { get; set; } = true;
    [ObservableProperty] public partial bool CanUnregister { get; set; }
    [ObservableProperty] public partial bool ShowOpenPasskeySettings { get; set; }

    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }
    public ICommand RefreshCommand    { get; }
    public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;

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
        PingStatus pingStatus)
    {
        PluginStatus            = pingStatus;
        CanRegister             = !isRegistered;
        CanUnregister           = isRegistered;
        ShowOpenPasskeySettings = isRegistered && !providerEnabled && !autoregisterError;

        Status = (autoregisterError, isRegistered, providerEnabled, pluginRunning, pingStatus) switch
        {
            (true,  _,     _,     _,     _)                          => ProviderStatus.AutoregisterFailed,
            (_,     false, _,     _,     _)                          => ProviderStatus.NotRegistered,
            (_,     _,     false, _,     _)                          => ProviderStatus.WaitingToBeEnabled,
            (_,     _,     _,     _,     PingStatus.IncompatibleVersion) => ProviderStatus.VersionMismatch,
            (_,     _,     _,     _,     PingStatus.NoDatabase)      => ProviderStatus.NoDatabase,
            (_,     _,     _,     false, _)                          => ProviderStatus.KeePassNotConnected,
            _                                                         => ProviderStatus.Ready,
        };
    }
}
