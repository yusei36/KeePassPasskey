using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;

namespace KeePassPasskeyProvider.App.ViewModel;

internal sealed partial class SetupGuideViewModel : ObservableObject
{
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;
    public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;

    partial void OnIsReadyChanged(bool value)
    {
        IsSetupExpanded = !value;
    }
}
