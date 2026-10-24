// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.Input;
using FluentAvalonia.UI.Controls;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Utils;

internal enum UnsavedChangesChoice { Save, Discard, Cancel }

internal static class DialogService
{
	public static async Task<UnsavedChangesChoice> ShowUnsavedChangesAsync()
	{
		if (Application.AppWindow is not { } mainWindow) return UnsavedChangesChoice.Cancel;

		var dialog = new FAContentDialog
		{
			Title = "Unsaved changes",
			Content = "You have unsaved settings. Save them before leaving?",
			PrimaryButtonText = "Save",
			SecondaryButtonText = "Discard",
			CloseButtonText = "Cancel",
			DefaultButton = FAContentDialogButton.Primary,
		};

		return await dialog.ShowAsync(mainWindow) switch
		{
			FAContentDialogResult.Primary => UnsavedChangesChoice.Save,
			FAContentDialogResult.Secondary => UnsavedChangesChoice.Discard,
			_ => UnsavedChangesChoice.Cancel,
		};
	}

	public static async Task ShowPluginInstallAsync()
	{
		if (Application.AppWindow is not { } mainWindow) return;

		var viewModel = new ViewModel.PluginInstallViewModel();
		var dialog = new FAContentDialog
		{
			Title = "KeePass plugin",
			Content = new Dialogs.PluginInstallDialog { DataContext = viewModel },
			SecondaryButtonText = "Remove",
			CloseButtonText = "Close",
		};

		void SyncButtons()
		{
			dialog.PrimaryButtonText = viewModel.PrimaryActionText;
			dialog.IsPrimaryButtonEnabled = viewModel.CanInstall && !viewModel.IsBusy;
			dialog.IsSecondaryButtonEnabled = viewModel.CanRemove && !viewModel.IsBusy;
			dialog.DefaultButton = viewModel.EmphasizePrimary
				? FAContentDialogButton.Primary
				: FAContentDialogButton.None;
		}

		// Install and Remove keep the dialog open: its result strip is where the outcome is reported.
		dialog.PrimaryButtonClick += async (_, args) => await RunAsync(args, viewModel.InstallCommand);
		dialog.SecondaryButtonClick += async (_, args) => await RunAsync(args, viewModel.RemoveCommand);
		viewModel.PropertyChanged += (_, _) => SyncButtons();
		SyncButtons();

		await dialog.ShowAsync(mainWindow);
	}

	private static async Task RunAsync(FAContentDialogButtonClickEventArgs args, IAsyncRelayCommand command)
	{
		args.Cancel = true;
		var deferral = args.GetDeferral();
		try { await command.ExecuteAsync(null); }
		finally { deferral.Complete(); }
	}

	public static async Task ShowErrorAsync(string title, string message)
	{
		if (Application.AppWindow is not { } mainWindow)
		{
			Log.Error($"Could not show error dialog: {title} - {message}");
			return;
		}

		var dialog = new FAContentDialog
		{
			Title = title,
			Content = message,
			CloseButtonText = "OK",
			DefaultButton = FAContentDialogButton.Close,
		};

		await dialog.ShowAsync(mainWindow);
	}
}
