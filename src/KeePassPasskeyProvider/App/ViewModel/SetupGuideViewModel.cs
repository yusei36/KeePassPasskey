// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class SetupGuideViewModel : ObservableObject
{
	[ObservableProperty] public partial bool IsSetupExpanded { get; set; } = true;
	[ObservableProperty] public partial bool IsReady { get; set; }
	[ObservableProperty] public partial bool ShowTrayOffer { get; set; }

	public ICommand OpenPasskeySettingsCommand => ProviderCommands.OpenPasskeySettingsCommand;
	public ICommand ShowPluginFileCommand => ProviderCommands.ShowPluginFileCommand;

	/// <summary>True when the bundled plugin DLL exists (gates the "Show KeePassPasskey.dll" button).</summary>
	public bool HasBundledPlugin => ProviderCommands.HasBundledPlugin;

	internal event EventHandler? TrayStateChanged;

	partial void OnIsReadyChanged(bool value)
	{
		IsSetupExpanded = !value;
		if (value && !AppSettings.Current.EnableTrayIcon
				  && !AppSettings.Current.TrayIconPromptShown)
			ShowTrayOffer = true;
	}

	[RelayCommand]
	private void EnableTrayFromOffer()
	{
		AppSettings.Current.EnableTrayIcon = true;
		AppSettings.Current.TrayIconPromptShown = true;
		AppSettings.Save(AppSettings.Current);
		ShowTrayOffer = false;
		TrayStateChanged?.Invoke(this, EventArgs.Empty);
	}

	[RelayCommand]
	private void OpenUserGuide() =>
		System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
		{
			FileName = "https://keepasspasskey.github.io/docs/user-guide/",
			UseShellExecute = true,
		});

	[RelayCommand]
	private void DismissTrayOffer()
	{
		AppSettings.Current.TrayIconPromptShown = true;
		AppSettings.Save(AppSettings.Current);
		ShowTrayOffer = false;
	}
}
