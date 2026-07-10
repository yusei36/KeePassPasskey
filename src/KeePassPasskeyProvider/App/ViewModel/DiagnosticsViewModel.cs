// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class DiagnosticsViewModel : ObservableObject, IDisposable
{
    [ObservableProperty] public partial string? ServerVersion { get; set; }
    [ObservableProperty] public partial PingStatus PingStatus { get; set; }
    public ICommand RegisterCommand   { get; }
    public ICommand UnregisterCommand { get; }
    public LogViewModel LogPanel { get; } = new LogViewModel();

    public string ServerVersionShort => ServerVersion != null ? ShortenVersion(ServerVersion) : "";
    public bool IsServerVersionAvailable => ServerVersion != null;
    public bool IsServerVersionNotAvailable => ServerVersion is null;
    public bool IsVersionMismatch => PingStatus == KeePassPasskeyShared.Ipc.PingStatus.IncompatibleVersion;

    public static string ClientVersion      => _appVersion;
    public static string ClientVersionShort => ShortenVersion(_appVersion);
    public static string LogDirPath         => Log.LogDir;

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

    internal DiagnosticsViewModel(ICommand register, ICommand unregister)
    {
        RegisterCommand   = register;
        UnregisterCommand = unregister;
    }

    public void Dispose() => LogPanel.Dispose();

    [RelayCommand]
    private async Task CopyToClipboard(string? text)
    {
        if (text is null) return;
        await Application.CopyToClipboardAsync(text);
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

    private static string ShortenVersion(string v)
        => Regex.Replace(v, @"\+([0-9a-f]{8})[0-9a-f]+", "+$1", RegexOptions.IgnoreCase);

    private static readonly string _appVersion =
            (Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "?");
}
