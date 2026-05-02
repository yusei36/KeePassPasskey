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
