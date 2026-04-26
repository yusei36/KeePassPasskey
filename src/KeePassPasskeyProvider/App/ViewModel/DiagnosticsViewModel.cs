using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

internal sealed partial class DiagnosticsViewModel : ObservableObject
{
    [ObservableProperty] private string? _serverVersion;
    [ObservableProperty] private PingStatus _pingStatus;
    [ObservableProperty] private bool _isLogVisible;
    [ObservableProperty] private string _logText = "";
    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }

    public string ServerVersionShort => ServerVersion != null ? ShortenVersion(ServerVersion) : "";
    public bool IsServerVersionAvailable => ServerVersion != null;
    public bool IsServerVersionNotAvailable => ServerVersion is null;
    public bool IsVersionMismatch => PingStatus == KeePassPasskey.Shared.Ipc.PingStatus.IncompatibleVersion;

    public static string ClientVersion    => _appVersion;
    public static string ClientVersionShort => ShortenVersion(_appVersion);

    partial void OnServerVersionChanged(string? value)
    {
        OnPropertyChanged(nameof(ServerVersionShort));
        OnPropertyChanged(nameof(IsServerVersionAvailable));
        OnPropertyChanged(nameof(IsServerVersionNotAvailable));
    }

    partial void OnPingStatusChanged(PingStatus value)
    {
        OnPropertyChanged(nameof(IsVersionMismatch));
    }

    partial void OnIsLogVisibleChanged(bool value)
    {
        if (value) ReloadLog();
    }

    public static string LogDirPath => Log.LogDir;

    [RelayCommand]
    private async Task CopyToClipboard(string? text)
    {
        if (text is null) return;
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime { MainWindow: { } win })
            await (TopLevel.GetTopLevel(win)?.Clipboard?.SetTextAsync(text) ?? Task.CompletedTask);
    }

    [RelayCommand]
    private void OpenLogDir()
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName        = LogDirPath,
            UseShellExecute = true,
        });
    }

    private readonly FileSystemWatcher? _logWatcher;

    internal DiagnosticsViewModel(ICommand register, ICommand unregister)
    {
        RegisterCommand   = register;
        UnregisterCommand = unregister;
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

    private static string ShortenVersion(string v)
        => Regex.Replace(v, @"\+([0-9a-f]{8})[0-9a-f]+", "+$1", RegexOptions.IgnoreCase);

    private static readonly string _appVersion =
            (Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "?");
}
