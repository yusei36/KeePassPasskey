using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using FluentAvalonia.UI.Controls;

namespace KeePassPasskeyProvider.Util;

internal static class DialogService
{
    public static async Task ShowErrorAsync(string title, string message)
    {
        if (Application.Current?.ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime { MainWindow: { } mainWindow })
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
