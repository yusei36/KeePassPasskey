using System.Diagnostics;
using System.Windows.Input;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskey.Shared.Ipc;

namespace KeePassPasskeyProvider.UI;

internal sealed partial class StatusHeroViewModel : ObservableObject
{
    [ObservableProperty] private string _headline = "";
    [ObservableProperty] private string _subhead = "";
    [ObservableProperty] private IBrush _ringBorderBrush = NeutralBrush;
    [ObservableProperty] private IBrush _ringBackgroundBrush = NeutralBgBrush;
    [ObservableProperty] private IBrush _pluginDotColor = NeutralBrush;
    [ObservableProperty] private string _pluginStatusText = "";
    [ObservableProperty] private IBrush _providerDotColor = NeutralBrush;
    [ObservableProperty] private string _providerPillLabel = "Not registered";
    [ObservableProperty] private bool _canRegister = true;
    [ObservableProperty] private bool _canUnregister;
    [ObservableProperty] private bool _showOpenPasskeySettings;
    [ObservableProperty] private bool _isReady;

    public bool IsNotReady => !IsReady;
    partial void OnIsReadyChanged(bool value) => OnPropertyChanged(nameof(IsNotReady));

    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }
    public ICommand RefreshCommand    { get; }

    [RelayCommand]
    private static void OpenPasskeySettings()
        => Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });

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
        PingStatus? pingStatus)
    {
        bool ready = pluginRunning && providerEnabled;
        IsReady = ready;

        // Ring
        if (ready)
        {
            RingBorderBrush     = SuccessBrush;
            RingBackgroundBrush = SuccessBgBrush;
        }
        else if (autoregisterError || !isRegistered)
        {
            RingBorderBrush     = CriticalBrush;
            RingBackgroundBrush = CriticalBgBrush;
        }
        else
        {
            RingBorderBrush     = WarningBrush;
            RingBackgroundBrush = WarningBgBrush;
        }

        // Headline + Subhead
        if (autoregisterError)
        {
            Headline = "Automatic registration failed";
            Subhead  = "You can retry by clicking Register.";
        }
        else if (!isRegistered)
        {
            Headline = "Not registered";
            Subhead  = "KeePassPasskey will register the provider automatically on launch.";
        }
        else if (!providerEnabled)
        {
            Headline = "Waiting to be enabled";
            Subhead  = "Enable KeePassPasskey in Windows Settings → Accounts → Passkeys.";
        }
        else if (pingStatus == PingStatus.IncompatibleVersion)
        {
            Headline = "Version mismatch";
            Subhead  = "Update the plugin or the provider so both are on the same version.";
        }
        else if (pingStatus == PingStatus.NoDatabase)
        {
            Headline = "No database open";
            Subhead  = "Open a KeePass database to use passkeys.";
        }
        else if (!pluginRunning)
        {
            Headline = "Plugin not running";
            Subhead  = "Start KeePass with the KeePassPasskey plugin installed.";
        }
        else
        {
            Headline = "All systems ready";
            Subhead  = "Provider is enabled and the KeePass plugin is running.";
        }

        // Plugin pill
        PluginStatusText = pingStatus switch
        {
            PingStatus.Ready               => "Running",
            PingStatus.NoDatabase          => "No database open",
            PingStatus.IncompatibleVersion => "Incompatible version",
            _                              => "Not running",
        };
        PluginDotColor = pingStatus switch
        {
            PingStatus.Ready               => SuccessBrush,
            PingStatus.NoDatabase          => WarningBrush,
            PingStatus.IncompatibleVersion => CriticalBrush,
            _                              => NeutralBrush,
        };

        // Provider pill
        if (providerEnabled)
        {
            ProviderDotColor  = SuccessBrush;
            ProviderPillLabel = "Enabled";
        }
        else if (isRegistered)
        {
            ProviderDotColor  = WarningBrush;
            ProviderPillLabel = "Registered";
        }
        else
        {
            ProviderDotColor  = NeutralBrush;
            ProviderPillLabel = "Not registered";
        }

        // Actions
        CanRegister             = !isRegistered;
        CanUnregister           = isRegistered;
        ShowOpenPasskeySettings = isRegistered && !providerEnabled && !autoregisterError;
    }

    private static readonly IBrush SuccessBrush    = new SolidColorBrush(Color.Parse("#6ccb5f"));
    private static readonly IBrush WarningBrush    = new SolidColorBrush(Color.Parse("#fce100"));
    private static readonly IBrush CriticalBrush   = new SolidColorBrush(Color.Parse("#ff99a4"));
    private static readonly IBrush SuccessBgBrush  = new SolidColorBrush(Color.FromArgb(0x26, 0x6c, 0xcb, 0x5f));
    private static readonly IBrush WarningBgBrush  = new SolidColorBrush(Color.FromArgb(0x1E, 0xfc, 0xe1, 0x00));
    private static readonly IBrush CriticalBgBrush = new SolidColorBrush(Color.FromArgb(0x26, 0xff, 0x99, 0xa4));
    private static readonly IBrush NeutralBrush    = new SolidColorBrush(Color.Parse("#8a8a8a"));
    private static readonly IBrush NeutralBgBrush  = new SolidColorBrush(Color.FromArgb(0x14, 0x8a, 0x8a, 0x8a));
}
