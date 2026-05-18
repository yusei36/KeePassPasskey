// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class SetupGuideViewModel : ObservableObject
{
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;
    [ObservableProperty] private bool _showTrayOffer;

    public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;

    internal event EventHandler? TrayStateChanged;

    partial void OnIsReadyChanged(bool value)
    {
        IsSetupExpanded = !value;
        if (value && !LocalProviderSettings.Current.EnableTrayIcon
                  && !LocalProviderSettings.Current.TrayIconPromptShown)
            ShowTrayOffer = true;
    }

    [RelayCommand]
    private void EnableTrayFromOffer()
    {
        LocalProviderSettings.Current.EnableTrayIcon     = true;
        LocalProviderSettings.Current.TrayIconPromptShown = true;
        LocalProviderSettings.Save(LocalProviderSettings.Current);
        ShowTrayOffer = false;
        TrayStateChanged?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void DismissTrayOffer()
    {
        LocalProviderSettings.Current.TrayIconPromptShown = true;
        LocalProviderSettings.Save(LocalProviderSettings.Current);
        ShowTrayOffer = false;
    }
}
