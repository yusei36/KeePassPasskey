// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace KeePassPasskeyProvider.Dashboard.ViewModel;

internal static class ProviderCommands
{
    internal static ICommand OpenPasskeySettingsCommand { get; } =
        new RelayCommand(OpenPasskeySettings);

    private static void OpenPasskeySettings()
        => Process.Start(new ProcessStartInfo("ms-settings:passkeys-advancedoptions") { UseShellExecute = true });
}
