using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Input;
using Avalonia.Media;
using Avalonia.Threading;
using KeePassPasskey.Shared;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Ipc;
using KeePassPasskeyProvider.Plugin;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.UI;

internal sealed class MainWindowViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _statusText = "Checking...";
    private string _pluginStatusText = "Checking...";
    private string _resultMessage = "";
    private IBrush _statusColor = Brushes.Gray;
    private IBrush _pluginStatusColor = Brushes.Gray;
    private string _logText = "";
    private bool _isLogVisible = false;

    private readonly FileSystemWatcher? _logWatcher;

    public string StatusText
    {
        get => _statusText;
        private set { _statusText = value; OnPropertyChanged(); }
    }

    public string PluginStatusText
    {
        get => _pluginStatusText;
        private set { _pluginStatusText = value; OnPropertyChanged(); }
    }

    public string ResultMessage
    {
        get => _resultMessage;
        private set { _resultMessage = value; OnPropertyChanged(); }
    }

    public IBrush StatusColor
    {
        get => _statusColor;
        private set { _statusColor = value; OnPropertyChanged(); }
    }

    public IBrush PluginStatusColor
    {
        get => _pluginStatusColor;
        private set { _pluginStatusColor = value; OnPropertyChanged(); }
    }

    public string LogText
    {
        get => _logText;
        private set { _logText = value; OnPropertyChanged(); }
    }

    public bool IsLogVisible
    {
        get => _isLogVisible;
        private set { _isLogVisible = value; OnPropertyChanged(); OnPropertyChanged(nameof(LogToggleLabel)); }
    }

    public string LogToggleLabel => _isLogVisible ? "Hide Log" : "Show Log";

    public bool IsNotPackaged { get; } = !IsRunningAsPackage();

    public ICommand RegisterCommand            { get; }
    public ICommand UnregisterCommand          { get; }
    public ICommand RefreshCommand             { get; }
    public ICommand OpenPasskeySettingsCommand { get; }
    public ICommand ToggleLogCommand           { get; }

    public MainWindowViewModel()
    {
        RegisterCommand            = new RelayCommand(DoRegister);
        UnregisterCommand          = new RelayCommand(DoUnregister);
        RefreshCommand             = new RelayCommand(DoManualRefresh);
        OpenPasskeySettingsCommand = new RelayCommand(DoOpenPasskeySettings);
        ToggleLogCommand           = new RelayCommand(DoToggleLog);
        DoRefresh();

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        timer.Tick += (_, _) => DoRefresh();
        timer.Start();

        // Watch the log file for changes
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

    private void DoRegister()
    {
        int hr = PluginRegistration.Register();
        ResultMessage = hr >= 0
            ? "Registered successfully."
            : $"Registration failed: 0x{hr:X8}";
        DoRefresh();
    }

    private void DoUnregister()
    {
        int hr = PluginRegistration.Unregister();
        ResultMessage = hr >= 0
            ? "Unregistered successfully."
            : $"Unregister failed: 0x{hr:X8}";
        DoRefresh();
    }

    private void DoToggleLog()
    {
        IsLogVisible = !IsLogVisible;
        if (IsLogVisible)
            ReloadLog();
    }

    private void ReloadLog()
    {
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

    private static void DoOpenPasskeySettings()
    {
        Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });
    }

    private void DoManualRefresh()
    {
        ResultMessage = "";
        DoRefresh();
    }

    private void DoRefresh()
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

        var pingRequest = new IpcRequest { Type = "ping" };
        bool ok = PipeClient.SendRequest(pingRequest, out var pingResponse);
        string pluginStatus = ok ? (pingResponse?.Status ?? "unknown") : "not_running";
        (PluginStatusText, PluginStatusColor) = pluginStatus switch
        {
            "ready"       => ("Running",          Brushes.Green),
            "no_database" => ("No database open", Brushes.OrangeRed),
            _             => ("Not running",       Brushes.Gray),
        };
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static bool IsRunningAsPackage()
    {
        const int APPMODEL_ERROR_NO_PACKAGE  = 15700;
        uint length = 0;
        int rc = GetCurrentPackageFullName(ref length, null);
        return rc != APPMODEL_ERROR_NO_PACKAGE;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, char[]? packageFullName);
}

internal sealed class RelayCommand(Action execute) : ICommand
{
#pragma warning disable CS0067 // currently not used, pragma needs to be removed once it is used
    public event EventHandler? CanExecuteChanged;
#pragma warning restore CS0067
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => execute();
}
