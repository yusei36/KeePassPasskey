// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
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

	private static readonly string _pluginLogFilePath = PluginLogFile.FilePath;
	private readonly DispatcherTimer _pollTimer;
	private (DateTime Time, long Length) _providerStamp;
	private (DateTime Time, long Length) _pluginStamp;

	public string CurrentLogFilePath => SelectedLogTabIndex == 0 ? Log.LogFilePath : _pluginLogFilePath;

	internal LogViewModel()
	{
		// The provider is packaged, so MSIX AppData redirection makes a FileSystemWatcher on the plugin's real-path log unreliable
		_pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
		_pollTimer.Tick += (_, _) => PollLogs();
	}

	partial void OnSelectedLogTabIndexChanged(int value) => OnPropertyChanged(nameof(CurrentLogFilePath));

	partial void OnIsLogVisibleChanged(bool value)
	{
		if (value)
		{
			_providerStamp = _pluginStamp = (DateTime.MinValue, -1);
			PollLogs();
			_pollTimer.Start();
		}
		else
		{
			_pollTimer.Stop();
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
		System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
		{
			FileName = CurrentLogFilePath,
			UseShellExecute = true,
		});
	}

	[RelayCommand]
	private void OpenLogDir()
	{
		string? dir = Path.GetDirectoryName(CurrentLogFilePath);
		if (dir == null) return;
		Directory.CreateDirectory(dir);
		System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
		{
			FileName = dir,
			UseShellExecute = true,
		});
	}

	public void Dispose() => _pollTimer.Stop();

	private void PollLogs()
	{
		ReloadIfChanged(Log.LogFilePath, ref _providerStamp, lines => ProviderLogLines = lines);
		ReloadIfChanged(_pluginLogFilePath, ref _pluginStamp, lines => PluginLogLines = lines);
	}

	private void ReloadIfChanged(string filePath, ref (DateTime Time, long Length) stamp, Action<IReadOnlyList<LogLine>> setLines)
	{
		(DateTime Time, long Length) current = default;
		try
		{
			var info = new FileInfo(filePath);
			if (info.Exists) current = (info.LastWriteTimeUtc, info.Length);
		}
		catch { /* treat as unchanged */ }
		if (current == stamp) return;
		stamp = current;
		ReloadLogFile(filePath, setLines);
	}

	private void ReloadLogFile(string filePath, Action<IReadOnlyList<LogLine>> setLines)
	{
		try
		{
			if (!File.Exists(filePath))
			{
				setLines([new LogLine("(no log file yet)", null)]);
				return;
			}
			using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			using var reader = new StreamReader(fs);
			string all = reader.ReadToEnd();
			string[] parts = all.Split('\n');
			string[] tail = parts.Length > 100 ? parts[^100..] : parts;
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
