// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Windows.Input;
using CommunityToolkit.Mvvm.Input;

namespace KeePassPasskeyProvider.App.ViewModel;

internal static class ProviderCommands
{
	internal static ICommand OpenPasskeySettingsCommand { get; } =
		new RelayCommand(OpenPasskeySettings);

	internal static ICommand ShowPluginFileCommand { get; } =
		new RelayCommand(ShowPluginFile);

	// Full path to the bundled plugin DLL, or null if not running packaged / not present.
	private static readonly string? BundledPluginDll = ResolveBundledPluginDll();

	/// <summary>True when the bundled plugin DLL exists (gates the "Show KeePassPasskey.dll" buttons).</summary>
	internal static bool HasBundledPlugin { get; } = BundledPluginDll != null && File.Exists(BundledPluginDll);

	private static void OpenPasskeySettings()
		=> Process.Start(new ProcessStartInfo("ms-settings:passkeys-advancedoptions") { UseShellExecute = true });

	private static void ShowPluginFile()
	{
		if (BundledPluginDll == null) return;
		Process.Start(new ProcessStartInfo
		{
			FileName = "explorer.exe",
			Arguments = $"/select,\"{BundledPluginDll}\"",
		});
	}

	private static string? ResolveBundledPluginDll()
	{
		try
		{
			var installPath = Windows.ApplicationModel.Package.Current.InstalledLocation.Path;
			return Path.Combine(installPath, "KeePassPasskeyPlugin", "KeePassPasskey.dll");
		}
		catch
		{
			return null;
		}
	}
}
