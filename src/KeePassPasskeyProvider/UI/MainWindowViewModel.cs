using System.Diagnostics;
using System.Runtime.InteropServices;
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Plugin;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.UI;

internal sealed partial class MainWindowViewModel : ObservableObject
{
    // StatusHero
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

    // SetupGuide
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;

    // Log
    [ObservableProperty] private string _logText = "";
    [ObservableProperty] private bool _isLogVisible;
    [ObservableProperty] private bool _isRefreshing;

    // Internal state
    private bool _pluginRunning;
    private bool _providerEnabled;
    private bool _isRegistered;
    private bool _autoregisterError;
    private PingStatus? _pingStatus;

    // Brushes
    private static readonly IBrush SuccessBrush    = new SolidColorBrush(Color.Parse("#6ccb5f"));
    private static readonly IBrush WarningBrush    = new SolidColorBrush(Color.Parse("#fce100"));
    private static readonly IBrush CriticalBrush   = new SolidColorBrush(Color.Parse("#ff99a4"));
    private static readonly IBrush SuccessBgBrush  = new SolidColorBrush(Color.FromArgb(0x26, 0x6c, 0xcb, 0x5f));
    private static readonly IBrush WarningBgBrush  = new SolidColorBrush(Color.FromArgb(0x1E, 0xfc, 0xe1, 0x00));
    private static readonly IBrush CriticalBgBrush = new SolidColorBrush(Color.FromArgb(0x26, 0xff, 0x99, 0xa4));
    private static readonly IBrush NeutralBrush    = new SolidColorBrush(Color.Parse("#8a8a8a"));
    private static readonly IBrush NeutralBgBrush  = new SolidColorBrush(Color.FromArgb(0x14, 0x8a, 0x8a, 0x8a));

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

    private void UpdateIsReady() => IsReady = _pluginRunning && _providerEnabled;

    private void UpdateStatusDisplay()
    {
        bool ready = _pluginRunning && _providerEnabled;

        // Ring
        if (ready)
        {
            RingBorderBrush     = SuccessBrush;
            RingBackgroundBrush = SuccessBgBrush;
        }
        else if (_autoregisterError || !_isRegistered)
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
        if (_autoregisterError)
        {
            Headline = "Automatic registration failed";
            Subhead  = "You can retry by clicking Register.";
        }
        else if (!_isRegistered)
        {
            Headline = "Not registered";
            Subhead  = "KeePassPasskey will register the provider automatically on launch.";
        }
        else if (!_providerEnabled)
        {
            Headline = "Waiting to be enabled";
            Subhead  = "Enable KeePassPasskey in Windows Settings → Accounts → Passkeys.";
        }
        else if (_pingStatus == PingStatus.IncompatibleVersion)
        {
            Headline = "Version mismatch";
            Subhead  = "Update the plugin or the provider so both are on the same version.";
        }
        else if (_pingStatus == PingStatus.NoDatabase)
        {
            Headline = "No database open";
            Subhead  = "Open a KeePass database to use passkeys.";
        }
        else if (!_pluginRunning)
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
        PluginDotColor = _pingStatus switch
        {
            PingStatus.Ready               => SuccessBrush,
            PingStatus.NoDatabase          => WarningBrush,
            PingStatus.IncompatibleVersion => CriticalBrush,
            _                              => NeutralBrush,
        };

        // Provider pill
        if (_providerEnabled)
        {
            ProviderDotColor  = SuccessBrush;
            ProviderPillLabel = "Enabled";
        }
        else if (_isRegistered)
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
        CanRegister             = !_isRegistered;
        CanUnregister           = _isRegistered;
        ShowOpenPasskeySettings = _isRegistered && !_providerEnabled && !_autoregisterError;
    }

    private readonly FileSystemWatcher? _logWatcher;
    private readonly PipeClient _pipeClient = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)));

    public bool IsNotPackaged { get; } = !IsRunningAsPackage();
    public static string AppVersion { get; } =
        "v" + (System.Reflection.CustomAttributeExtensions
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(
                System.Reflection.Assembly.GetEntryAssembly()!)
            ?.InformationalVersion ?? "?");

    public MainWindowViewModel()
    {
        AutoRegisterIfNeeded();
        DoRefresh();

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        timer.Tick += (_, _) => DoRefresh();
        timer.Start();

        string logDir  = Path.GetDirectoryName(Log.LogFilePath)!;
        string logFile = Path.GetFileName(Log.LogFilePath);
        if (Directory.Exists(logDir))
        {
            _logWatcher = new FileSystemWatcher(logDir, logFile)
            {
                NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true,
            };
            _logWatcher.Changed += (_, _) => Dispatcher.UIThread.Post(ReloadLog);
            _logWatcher.Created += (_, _) => Dispatcher.UIThread.Post(ReloadLog);
        }
    }

    private void AutoRegisterIfNeeded()
    {
        int stateHr = PluginRegistration.GetState(out _);
        if (stateHr >= 0) return;

        int hr = PluginRegistration.Register();
        _autoregisterError = hr < 0;
    }

    [RelayCommand]
    private void Register()
    {
        _autoregisterError = false;
        int hr = PluginRegistration.Register();
        if (hr < 0) _autoregisterError = true;
        DoRefresh();
    }

    [RelayCommand]
    private void Unregister()
    {
        _autoregisterError = false;
        PluginRegistration.Unregister();
        DoRefresh();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        RefreshProviderStatus();
        ApplyPingResponse(await Task.Run(() => _pipeClient.Ping()));
        IsRefreshing = false;
    }

    [RelayCommand]
    private static void OpenPasskeySettings()
        => Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });

    partial void OnIsLogVisibleChanged(bool value)
    {
        if (value) ReloadLog();
    }

    private void ReloadLog()
    {
        if (!IsLogVisible) return;
        try
        {
            if (!File.Exists(Log.LogFilePath))
            {
                LogText = "(no log file yet)";
                return;
            }
            using var fs     = new FileStream(Log.LogFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);
            string all   = reader.ReadToEnd();
            string[] lines = all.Split('\n');
            LogText = lines.Length > 100 ? string.Join('\n', lines[^100..]) : all;
        }
        catch (Exception ex)
        {
            LogText = $"(could not read log: {ex.Message})";
        }
    }

    private void DoRefresh()
    {
        RefreshProviderStatus();
        ApplyPingResponse(_pipeClient.Ping());
    }

    private void RefreshProviderStatus()
    {
        int hr = PluginRegistration.GetState(out var state);
        _isRegistered    = hr >= 0;
        _providerEnabled = hr >= 0 && state == AuthenticatorState.AuthenticatorState_Enabled;
        UpdateIsReady();
        UpdateStatusDisplay();
    }

    private void ApplyPingResponse(PingResponse? pingResponse)
    {
        _pingStatus    = pingResponse?.Status;
        _pluginRunning = _pingStatus == PingStatus.Ready;

        PluginStatusText = _pingStatus switch
        {
            PingStatus.Ready               => "Running",
            PingStatus.NoDatabase          => "No database open",
            PingStatus.IncompatibleVersion => "Incompatible version",
            _                              => "Not running",
        };

        UpdateIsReady();
        UpdateStatusDisplay();
        Log.Info($"ApplyPingResponse: status: {_pingStatus?.ToString() ?? "no response"}, clientVersion: {PipeConstants.Version}, serverVersion: {pingResponse?.Version}");
    }

    private static bool IsRunningAsPackage()
    {
        const int APPMODEL_ERROR_NO_PACKAGE = 15700;
        uint length = 0;
        int rc = GetCurrentPackageFullName(ref length, null);
        return rc != APPMODEL_ERROR_NO_PACKAGE;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, char[]? packageFullName);
}
