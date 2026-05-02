using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Dashboard.ViewModel;

public sealed partial class StatusHeroViewModel : ObservableObject
{
    [ObservableProperty] private ProviderStatus _status;
    [ObservableProperty] private PingStatus _pluginStatus;
    [ObservableProperty] private bool _canRegister = true;
    [ObservableProperty] private bool _canUnregister;
    [ObservableProperty] private bool _showOpenPasskeySettings;

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
            (_,     _,     _,     false, _)                          => ProviderStatus.PluginNotRunning,
            _                                                         => ProviderStatus.Ready,
        };
    }
}
