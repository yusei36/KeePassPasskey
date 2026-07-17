// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class MainWindowViewModel : ObservableObject
{
	public StatusHeroViewModel StatusHero { get; }
	public SetupGuideViewModel SetupGuide { get; }
	public DiagnosticsViewModel Diagnostics { get; }
	public SettingsViewModel Settings { get; }

	[ObservableProperty] public partial bool IsRefreshing { get; set; }

	public bool IsNotPackaged { get; } = !IsRunningAsPackage();

	public bool IsDevBuild => PluginConstants.Channel == DistributionChannel.Dev;

	public string WindowTitle => IsDevBuild ? "KeePassPasskey Dev" : "KeePassPasskey";

	internal event EventHandler? TrayStateChanged;

	internal void RaiseTrayStateChanged()
	{
		bool enabled = AppSettings.Current.EnableTrayIcon;
		if (enabled)
			SetupGuide.ShowTrayOffer = false;
		Settings.ReloadTrayIconState();
		TrayStateChanged?.Invoke(this, EventArgs.Empty);
		_ = SettingsViewModel.SetTrayStartupTaskAsync(enabled);
	}

	// Internal provider state
	private bool _pluginRunning;
	private bool _providerEnabled;
	private bool _isRegistered;
	private bool _autoregisterError;
	private PingStatus _pingStatus;
	private string? _serverVersion;

	private readonly PipeClient _pipeClient = new(msg => Log.Debug(msg, nameof(PipeClient)));

	public MainWindowViewModel(bool autoRegisterSucceeded = true)
	{
		_autoregisterError = !autoRegisterSucceeded;
		var registerCmd = new AsyncRelayCommand(RegisterAsync);
		var unregisterCmd = new AsyncRelayCommand(UnregisterAsync);
		var refreshCmd = new AsyncRelayCommand(RefreshAsync);

		StatusHero = new StatusHeroViewModel(registerCmd, unregisterCmd, refreshCmd);
		SetupGuide = new SetupGuideViewModel();
		Diagnostics = new DiagnosticsViewModel(registerCmd, unregisterCmd);
		Settings = new SettingsViewModel();

		Settings.TrayStateChanged += (_, _) => RaiseTrayStateChanged();
		SetupGuide.TrayStateChanged += (_, _) => RaiseTrayStateChanged();

		Directory.CreateDirectory(AppPaths.SettingsDir);
		var settingsWatcher = new FileSystemWatcher(AppPaths.SettingsDir)
		{
			Filter = SettingsCache.SettingsFileName,
			NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
			EnableRaisingEvents = true,
		};
		void ReloadSettings(object? _, FileSystemEventArgs __)
		{
			var updated = SettingsCache.TryLoad();
			if (updated == null) return;
			KeePassPasskeySettings.Current = updated;
			Dispatcher.UIThread.Post(Settings.ReloadFromCurrent);
		}
		settingsWatcher.Changed += ReloadSettings;
		settingsWatcher.Created += ReloadSettings;
		settingsWatcher.Renamed += (s, e) => ReloadSettings(s, e);

		DoRefresh();

		var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(KeePassPasskeySettings.Current.StatusRefreshIntervalMilliseconds) };
		timer.Tick += (_, _) => DoRefresh();
		timer.Start();
	}

	private async Task RegisterAsync()
	{
		_autoregisterError = false;
		int hr = PluginRegistration.Register();
		if (hr < HResults.S_OK)
		{
			_autoregisterError = true;
			await ShowPluginRegistrationErrorAsync("Register", hr);
		}
		else
		{
			DoRefresh();
		}
	}

	private async Task UnregisterAsync()
	{
		_autoregisterError = false;
		int hr = PluginRegistration.Unregister();
		if (hr < HResults.S_OK)
		{
			await ShowPluginRegistrationErrorAsync("Unregister", hr);
		}
		else
		{
			DoRefresh();
		}
	}

	private async Task RefreshAsync()
	{
		IsRefreshing = true;
		RefreshProviderStatus();
		ApplyPingResponse(await Task.Run(() => _pipeClient.Ping()));
		IsRefreshing = false;
	}

	private void DoRefresh()
	{
		RefreshProviderStatus();
		ApplyPingResponse(_pipeClient.Ping());
	}

	private void RefreshProviderStatus()
	{
		int hr = PluginRegistration.GetState(out var state);
		_isRegistered = hr >= HResults.S_OK;
		_providerEnabled = hr >= HResults.S_OK && state == AuthenticatorState.AuthenticatorState_Enabled;
		UpdateChildren();
	}

	private void ApplyPingResponse(PingResponse? pingResponse)
	{
		bool wasRunning = _pluginRunning;
		_pingStatus = pingResponse?.Status ?? PingStatus.NotConnected;
		_pluginRunning = _pingStatus == PingStatus.Ready;

		if (_pluginRunning && !wasRunning)
			_ = Settings.SyncFromKeePassAsync();

		_serverVersion = pingResponse?.Version;
		Diagnostics.ServerVersion = _serverVersion;
		Diagnostics.PingStatus = _pingStatus;
		UpdateChildren();

		Log.Info($"status: {_pingStatus}, clientVersion: {PipeConstants.Version}, serverVersion: {pingResponse?.Version}");
	}

	private void UpdateChildren()
	{
		StatusHero.Update(_pluginRunning, _providerEnabled, _isRegistered, _autoregisterError, _pingStatus, _serverVersion);
		SetupGuide.IsReady = _pluginRunning && _providerEnabled;
	}

	private static Task ShowPluginRegistrationErrorAsync(string operation, int hr)
	{
		string title = $"{operation} failed";
		string message =
			$"Windows returned HRESULT 0x{hr:X8} while trying to {operation.ToLowerInvariant()} the passkey provider.";
		return DialogService.ShowErrorAsync(title, message);
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
