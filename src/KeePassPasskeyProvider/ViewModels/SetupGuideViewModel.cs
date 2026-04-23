using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace KeePassPasskeyProvider.ViewModels;

internal sealed partial class SetupGuideViewModel : ObservableObject
{
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;

    public string SetupSubtitle => IsReady
        ? "Everything's in place — tap to review"
        : "4 steps to get KeePassPasskey working";

    public bool IsNotReady => !IsReady;

    partial void OnIsReadyChanged(bool value)
    {
        IsSetupExpanded = !value;
        OnPropertyChanged(nameof(SetupSubtitle));
        OnPropertyChanged(nameof(IsNotReady));
    }

    [RelayCommand]
    private static void OpenPasskeySettings()
        => Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });
}
