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
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(LogToggleLabel))] private bool _isLogVisible;
    [ObservableProperty] private bool _isRefreshing;

    private readonly FileSystemWatcher? _logWatcher;
    private readonly PipeClient _pipeClient = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)));

    public string LogToggleLabel => IsLogVisible ? "Hide Log" : "Show Log";
    public bool IsNotPackaged { get; } = !IsRunningAsPackage();

    public MainWindowViewModel()
    {
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

    [RelayCommand]
    private void ToggleLog()
    {
        IsLogVisible = !IsLogVisible;
        if (IsLogVisible)
            ReloadLog();
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
            LogText = reader.ReadToEnd();
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
        }
        else
        {
            StatusText  = $"Unknown or not registered (0x{hr:X8})";
            StatusColor = Brushes.Gray;
        }
    }

    private void ApplyPingResponse(PingResponse? pingResponse)
    {
        (PluginStatusText, PluginStatusColor) = pingResponse?.Status switch
        {
            PingStatus.Ready      => ("Running",          Brushes.Green),
            PingStatus.NoDatabase => ("No database open", Brushes.OrangeRed),
            _                     => ("Not running",       Brushes.Gray),
        };
        Log.Info($"status: {pingResponse?.Status.ToString() ?? "no response"}");
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
