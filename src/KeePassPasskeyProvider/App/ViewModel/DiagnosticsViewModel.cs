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
	public ICommand RegisterCommand { get; }
	public ICommand UnregisterCommand { get; }
	public LogViewModel LogPanel { get; } = new LogViewModel();

	public string ServerVersionShort => ServerVersion != null ? ShortenVersion(ServerVersion) : "";
	public bool IsServerVersionAvailable => ServerVersion != null;
	public bool IsServerVersionNotAvailable => ServerVersion is null;
	public bool IsIncompatibleVersion => PingStatus == KeePassPasskeyShared.Ipc.PingStatus.IncompatibleVersion;
	public string IncompatibleVersionMessage =>
		Util.Notifier.VersionMismatchBody(ClientVersion, ServerVersion) + " Passkey operations are blocked until then.";

	public bool IsVersionMismatch =>
		PingStatus == KeePassPasskeyShared.Ipc.PingStatus.Ready && ProductVersionsDiffer(ServerVersion);
	public string VersionMismatchMessage => VersionDifferenceMessage(ServerVersion);

	internal static string VersionDifferenceMessage(string? pluginVersion) =>
		$"This app ({PipeConstants.StripBuildMetadata(ClientVersion)}) and the KeePass plugin ({PipeConstants.StripBuildMetadata(pluginVersion ?? "")}) " +
		"have different versions but are compatible. Passkeys keep working, but new features might not be available until the older side is updated.";

	internal static bool ProductVersionsDiffer(string? pluginVersion)
		=> pluginVersion != null
		   && PipeConstants.StripBuildMetadata(ClientVersion) != PipeConstants.StripBuildMetadata(pluginVersion);

	public static string ClientVersion => _appVersion;
	public static string ClientVersionShort => ShortenVersion(_appVersion);
	public static string ClientVersionWithChannel => $"{ClientVersion} ({Authenticator.PluginConstants.ChannelDisplayName})";

	partial void OnServerVersionChanged(string? value)
	{
		OnPropertyChanged(nameof(ServerVersionShort));
		OnPropertyChanged(nameof(IsServerVersionAvailable));
		OnPropertyChanged(nameof(IsServerVersionNotAvailable));
		OnPropertyChanged(nameof(IncompatibleVersionMessage));
		OnPropertyChanged(nameof(IsVersionMismatch));
		OnPropertyChanged(nameof(VersionMismatchMessage));
	}

	partial void OnPingStatusChanged(PingStatus value)
	{
		OnPropertyChanged(nameof(IsIncompatibleVersion));
		OnPropertyChanged(nameof(IsVersionMismatch));
	}

	internal DiagnosticsViewModel(ICommand register, ICommand unregister)
	{
		RegisterCommand = register;
		UnregisterCommand = unregister;
	}

	public void Dispose() => LogPanel.Dispose();

	[RelayCommand]
	private async Task CopyToClipboard(string? text)
	{
		if (text is null) return;
		await Application.CopyToClipboardAsync(text);
	}

	private static string ShortenVersion(string v)
		=> Regex.Replace(v, @"\+([0-9a-f]{8})[0-9a-f]+", "+$1", RegexOptions.IgnoreCase);

	private static readonly string _appVersion =
			(Assembly.GetEntryAssembly()
			?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
			?.InformationalVersion ?? "?");
}
