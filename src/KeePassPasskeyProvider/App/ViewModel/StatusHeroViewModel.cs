// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class StatusHeroViewModel : ObservableObject
{
	[ObservableProperty] public partial ProviderStatus Status { get; set; }
	[ObservableProperty] public partial string Subhead { get; set; } = "";
	[ObservableProperty] public partial PluginPillState PluginStatus { get; set; }
	[ObservableProperty] public partial bool CanRegister { get; set; } = true;
	[ObservableProperty] public partial bool CanUnregister { get; set; }
	[ObservableProperty] public partial bool ShowOpenPasskeySettings { get; set; }
	[ObservableProperty] public partial bool ShowPluginFile { get; set; }

	public ICommand RegisterCommand { get; }
	public ICommand UnregisterCommand { get; }
	public ICommand RefreshCommand { get; }
	public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;
	public ICommand InstallPluginCommand => ProviderCommands.InstallPluginCommand;

	internal StatusHeroViewModel(ICommand register, ICommand unregister, ICommand refresh)
	{
		RegisterCommand = register;
		UnregisterCommand = unregister;
		RefreshCommand = refresh;
		AppLanguage.Changed += (_, _) => Subhead = ComputeSubhead();
	}

	private string? _pluginVersion;

	internal void Update(
		bool pluginRunning,
		bool providerEnabled,
		bool isRegistered,
		bool autoregisterError,
		PingStatus pingStatus,
		string? pluginVersion)
	{
		PluginStatus = pingStatus switch
		{
			PingStatus.IncompatibleVersion => PluginPillState.IncompatibleVersion,
			PingStatus.NoDatabase => PluginPillState.NoDatabase,
			PingStatus.Ready => DiagnosticsViewModel.ProductVersionsDiffer(pluginVersion)
				? PluginPillState.VersionMismatch
				: PluginPillState.Running,
			_ => PluginPillState.NotConnected,
		};
		CanRegister = !isRegistered;
		CanUnregister = isRegistered;
		ShowOpenPasskeySettings = isRegistered && !providerEnabled && !autoregisterError;

		Status = (autoregisterError, isRegistered, providerEnabled, pluginRunning, pingStatus) switch
		{
			(true, _, _, _, _) => ProviderStatus.AutoregisterFailed,
			(_, false, _, _, _) => ProviderStatus.NotRegistered,
			(_, _, false, _, _) => ProviderStatus.WaitingToBeEnabled,
			(_, _, _, _, PingStatus.IncompatibleVersion) => ProviderStatus.IncompatibleVersion,
			(_, _, _, _, PingStatus.NoDatabase) => ProviderStatus.NoDatabase,
			(_, _, _, false, _) => ProviderStatus.KeePassNotConnected,
			_ => DiagnosticsViewModel.ProductVersionsDiffer(pluginVersion)
				? ProviderStatus.VersionMismatch
				: ProviderStatus.Ready,
		};

		_pluginVersion = pluginVersion;
		Subhead = ComputeSubhead();

		// On a version difference the bundled plugin only helps when the plugin is the older side.
		ShowPluginFile = ProviderCommands.HasBundledPlugin
			&& (Status == ProviderStatus.KeePassNotConnected
				|| (Status is ProviderStatus.IncompatibleVersion or ProviderStatus.VersionMismatch
					&& PipeConstants.CompareProductVersions(DiagnosticsViewModel.ClientVersion, pluginVersion) > 0));
	}

	private string ComputeSubhead()
	{
		return Status switch
		{
			ProviderStatus.AutoregisterFailed => Strings.App_Status_Hint_AutoregisterFailed,
			ProviderStatus.NotRegistered => Strings.App_Status_Hint_NotRegistered,
			ProviderStatus.WaitingToBeEnabled => Strings.App_Status_Hint_WaitingToBeEnabled,
			ProviderStatus.IncompatibleVersion => Notifier.VersionMismatchBody(DiagnosticsViewModel.ClientVersion, _pluginVersion),
			ProviderStatus.VersionMismatch => DiagnosticsViewModel.VersionDifferenceMessage(_pluginVersion),
			ProviderStatus.NoDatabase => Strings.App_Status_Hint_NoDatabase,
			ProviderStatus.KeePassNotConnected => Strings.App_Status_Hint_KeePassNotConnected,
			_ => Strings.App_Status_Hint_Ready,
		};
	}
}
