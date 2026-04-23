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
    [ObservableProperty] private string _statusText = "Checking...";
    [ObservableProperty] private string _pluginStatusText = "Checking...";
    [ObservableProperty] private string _resultMessage = "";
    [ObservableProperty] private IBrush _statusColor = Brushes.Gray;
    [ObservableProperty] private IBrush _pluginStatusColor = Brushes.Gray;
    [ObservableProperty] private string _logText = "";
    [ObservableProperty] private bool _isLogVisible;
    [ObservableProperty] private bool _isRefreshing;
    [ObservableProperty] private bool _isSetupExpanded = true;
    [ObservableProperty] private bool _isReady;

    private bool _pluginRunning;
    private bool _providerEnabled;

    public string SetupSubtitle => IsReady
        ? "Everything's in place — tap to review"
        : "4 steps to get KeePassPasskey working";

    partial void OnIsReadyChanged(bool value)
    {
        IsSetupExpanded = !value;
        OnPropertyChanged(nameof(SetupSubtitle));
    }

    private void UpdateIsReady() => IsReady = _pluginRunning && _providerEnabled;

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
        if (stateHr >= 0) return; // already registered

        int hr = PluginRegistration.Register();
        ResultMessage = hr >= 0 ? "Registered automatically." : $"Auto-registration failed: 0x{hr:X8}";
    }

    [RelayCommand]
    private void Register()
    {
        int hr = PluginRegistration.Register();
        ResultMessage = hr >= 0 ? "Registered successfully." : $"Registration failed: 0x{hr:X8}";
        DoRefresh();
    }

    [RelayCommand]
    private void Unregister()
    {
        int hr = PluginRegistration.Unregister();
        ResultMessage = hr >= 0 ? "Unregistered successfully." : $"Unregister failed: 0x{hr:X8}";
        DoRefresh();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        ResultMessage = "";
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
            // Open with share so the log writer is not blocked
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
        if (hr >= 0)
        {
            bool enabled = state == AuthenticatorState.AuthenticatorState_Enabled;
            StatusText  = enabled ? "Enabled" : "Disabled";
            StatusColor = enabled ? Brushes.Green : Brushes.OrangeRed;
            _providerEnabled = enabled;
        }
        else
        {
            StatusText  = $"Unknown or not registered (0x{hr:X8})";
            StatusColor = Brushes.Gray;
            _providerEnabled = false;
        }
        UpdateIsReady();
    }

    private void ApplyPingResponse(PingResponse? pingResponse)
    {
        (PluginStatusText, PluginStatusColor) = pingResponse?.Status switch
        {
            PingStatus.Ready                => ("Running",              Brushes.Green),
            PingStatus.NoDatabase           => ("No database open",    Brushes.OrangeRed),
            PingStatus.IncompatibleVersion  => ("Incompatible version", Brushes.OrangeRed),
            _                               => ("Not running",          Brushes.Gray),
        };
        _pluginRunning = pingResponse?.Status == PingStatus.Ready;
        UpdateIsReady();
        var status = pingResponse == null ? "no response" : pingResponse.Status.ToString();
        Log.Info($"status: {status}, clientVersion: {PipeConstants.Version}, serverVersion: {pingResponse?.Version}");
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
