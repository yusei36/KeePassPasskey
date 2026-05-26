// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using FluentAvalonia.UI.Controls;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Utils;

internal static class DialogService
{
    public static async Task ShowErrorAsync(string title, string message)
    {
        if (Application.AppWindow is not { } mainWindow)
        {
            Log.Error($"Could not show error dialog: {title} - {message}");
            return;
        }

        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            CloseButtonText = "OK",
            DefaultButton = ContentDialogButton.Close,
        };

        await dialog.ShowAsync(mainWindow);
    }
}
