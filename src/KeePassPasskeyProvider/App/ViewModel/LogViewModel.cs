// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed record LogLine(string Text, LogLevel? Level);

public sealed partial class LogViewModel : ObservableObject, IDisposable
{
    [ObservableProperty] public partial IReadOnlyList<LogLine> ProviderLogLines { get; set; } = [];
    [ObservableProperty] public partial IReadOnlyList<LogLine> PluginLogLines { get; set; } = [];
    [ObservableProperty] public partial int SelectedLogTabIndex { get; set; }
    [ObservableProperty] public partial bool IsLogVisible { get; set; }

    private readonly FileSystemWatcher? _providerLogWatcher;
    private readonly FileSystemWatcher? _pluginLogWatcher;
    private static readonly string _pluginLogFilePath = Path.Combine(Log.LogDir, "Plugin.log");

    internal LogViewModel()
    {
        string logDir = Path.GetDirectoryName(Log.LogFilePath)!;
        if (Directory.Exists(logDir))
        {
            _providerLogWatcher = CreateWatcher(logDir, Path.GetFileName(Log.LogFilePath), ReloadProviderLog);
            _pluginLogWatcher = CreateWatcher(logDir, Path.GetFileName(_pluginLogFilePath), ReloadPluginLog);
        }
    }

    partial void OnIsLogVisibleChanged(bool value)
    {
        if (value)
        {
            ReloadProviderLog();
            ReloadPluginLog();
        }
    }

    [RelayCommand]
    private async Task CopyLog()
    {
        var lines = SelectedLogTabIndex == 0 ? ProviderLogLines : PluginLogLines;
        string text = string.Join(Environment.NewLine, lines.Select(l => l.Text));
        await Application.CopyToClipboardAsync(text);
    }

    [RelayCommand]
    private void OpenLogFile()
    {
        string path = SelectedLogTabIndex == 0 ? Log.LogFilePath : _pluginLogFilePath;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName        = path,
            UseShellExecute = true,
        });
    }

    public void Dispose()
    {
        _providerLogWatcher?.Dispose();
        _pluginLogWatcher?.Dispose();
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

    private void ReloadProviderLog() => ReloadLogFile(Log.LogFilePath, lines => ProviderLogLines = lines);

    private void ReloadPluginLog() => ReloadLogFile(_pluginLogFilePath, lines => PluginLogLines = lines);

    private void ReloadLogFile(string filePath, Action<IReadOnlyList<LogLine>> setLines)
    {
        if (!IsLogVisible) return;
        try
        {
            if (!File.Exists(filePath))
            {
                setLines([new LogLine("(no log file yet)", null)]);
                return;
            }
            using var fs     = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);
            string all       = reader.ReadToEnd();
            string[] parts   = all.Split('\n');
            string[] tail    = parts.Length > 100 ? parts[^100..] : parts;
            setLines(tail.Select(l => ParseLine(l.TrimEnd('\r'))).ToList());
        }
        catch (Exception ex)
        {
            setLines([new LogLine($"(could not read log: {ex.Message})", null)]);
        }
    }

    private static LogLine ParseLine(string line)
    {
        if (line.Contains("[ERROR]")) return new LogLine(line, LogLevel.Error);
        if (line.Contains("[WARN ]")) return new LogLine(line, LogLevel.Warn);
        if (line.Contains("[INFO ]")) return new LogLine(line, LogLevel.Info);
        if (line.Contains("[DEBUG]")) return new LogLine(line, LogLevel.Debug);
        return new LogLine(line, null);
    }
}
