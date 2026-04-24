using System.Diagnostics;
using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace KeePassPasskeyProvider.App.ViewModel;

internal static class ProviderCommands
{
    internal static ICommand OpenPasskeySettingsCommand { get; } =
        new RelayCommand(OpenPasskeySettings);

    private static void OpenPasskeySettings()
        => Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });
}
