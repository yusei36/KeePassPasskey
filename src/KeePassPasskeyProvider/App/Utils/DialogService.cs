// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
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
