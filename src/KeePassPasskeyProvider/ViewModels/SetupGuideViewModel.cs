using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;

namespace KeePassPasskeyProvider.ViewModels;

internal sealed partial class SetupGuideViewModel : ObservableObject
{
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;
    public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;

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
}
