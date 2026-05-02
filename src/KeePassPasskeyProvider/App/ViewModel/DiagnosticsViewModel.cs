using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Input;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class DiagnosticsViewModel : ObservableObject
{
    [ObservableProperty] private string? _serverVersion;
    [ObservableProperty] private PingStatus _pingStatus;
    [ObservableProperty] private bool _isLogVisible;
    [ObservableProperty] private string _logText = "";
    [ObservableProperty] private string _pluginLogText = "";
    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }

    public string ServerVersionShort => ServerVersion != null ? ShortenVersion(ServerVersion) : "";
    public bool IsServerVersionAvailable => ServerVersion != null;
    public bool IsServerVersionNotAvailable => ServerVersion is null;
    public bool IsVersionMismatch => PingStatus == KeePassPasskeyShared.Ipc.PingStatus.IncompatibleVersion;

    public static string ClientVersion     => _appVersion;
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
        if (value)
        {
            ReloadLog();
            ReloadPluginLog();
        }
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
    private readonly FileSystemWatcher? _pluginLogWatcher;

    private static readonly string _pluginLogFilePath = Path.Combine(Log.LogDir, "Plugin.log");

    internal DiagnosticsViewModel(ICommand register, ICommand unregister)
    {
        RegisterCommand   = register;
        UnregisterCommand = unregister;

        string logDir = Path.GetDirectoryName(Log.LogFilePath)!;
        if (Directory.Exists(logDir))
        {
            _logWatcher = CreateWatcher(logDir, Path.GetFileName(Log.LogFilePath), ReloadLog);
            _pluginLogWatcher = CreateWatcher(logDir, Path.GetFileName(_pluginLogFilePath), ReloadPluginLog);
        }
    }

    private static FileSystemWatcher CreateWatcher(string dir, string file, Action reload)
    {
        var watcher = new FileSystemWatcher(dir, file)
        {
            NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true,
        };
        watcher.Changed += (_, _) => Dispatcher.UIThread.Post(reload);
        watcher.Created += (_, _) => Dispatcher.UIThread.Post(reload);
        return watcher;
    }

    private void ReloadLog() => ReloadLogFile(Log.LogFilePath, text => LogText = text);

    private void ReloadPluginLog() => ReloadLogFile(_pluginLogFilePath, text => PluginLogText = text);

    private void ReloadLogFile(string filePath, Action<string> setText)
    {
        if (!IsLogVisible) return;
        try
        {
            if (!File.Exists(filePath))
            {
                setText("(no log file yet)");
                return;
            }
            using var fs     = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);
            string all       = reader.ReadToEnd();
            string[] lines   = all.Split('\n');
            setText(lines.Length > 100 ? string.Join('\n', lines[^100..]) : all);
        }
        catch (Exception ex)
        {
            setText($"(could not read log: {ex.Message})");
        }
    }

    private static string ShortenVersion(string v)
        => Regex.Replace(v, @"\+([0-9a-f]{8})[0-9a-f]+", "+$1", RegexOptions.IgnoreCase);

    private static readonly string _appVersion =
            (Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "?");
}
