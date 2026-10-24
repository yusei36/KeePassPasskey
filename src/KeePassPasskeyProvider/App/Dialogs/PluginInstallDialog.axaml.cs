// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Dialogs;

public partial class PluginInstallDialog : UserControl
{
	public PluginInstallDialog() => InitializeComponent();

	private void InitializeComponent() => AvaloniaXamlLoader.Load(this);

	private async void OnBrowse(object? sender, RoutedEventArgs e)
	{
		if (DataContext is not PluginInstallViewModel vm) return;
		if (Application.AppWindow is not { } window) return;

		var folders = await window.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
		{
			Title = "Select the KeePass folder, its Plugins folder, or a subfolder of it",
			AllowMultiple = false,
			SuggestedStartLocation = await SuggestedStart(window, vm),
		});

		string? path = folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
		if (!string.IsNullOrEmpty(path))
			vm.SelectedFolder = path;
	}

	private static async Task<IStorageFolder?> SuggestedStart(Window window, PluginInstallViewModel vm)
	{
		try
		{
			return string.IsNullOrWhiteSpace(vm.SelectedFolder)
				? null
				: await window.StorageProvider.TryGetFolderFromPathAsync(vm.SelectedFolder);
		}
		catch
		{
			return null;
		}
	}
}
