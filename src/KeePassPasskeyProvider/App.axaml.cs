// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using KeePassPasskeyProvider.App;
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider;

public class Application : Avalonia.Application
{
    private TrayIconService? _trayIconService;
    private MainWindow? _window;

    internal static Window? AppWindow => (Avalonia.Application.Current as Application)?._window;

    internal static async Task CopyToClipboardAsync(string text)
    {
        if (AppWindow is { } win)
            await (TopLevel.GetTopLevel(win)?.Clipboard?.SetTextAsync(text) ?? Task.CompletedTask);
    }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            SettingsViewModel.ApplyTheme(AppSettings.Current.Theme);
            bool autoRegisterSucceeded = PluginRegistration.EnsureRegistered();
            var vm = new MainWindowViewModel(autoRegisterSucceeded);
            _window = new MainWindow(vm);

            if (Program.StartHidden)
            {
                // Don't assign desktop.MainWindow so Avalonia never auto-shows it.
                // The tray icon will show it on demand.
                desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            }
            else
            {
                desktop.MainWindow = _window;
            }

            ApplyTrayState(desktop, vm);
            vm.TrayStateChanged += (_, _) => ApplyTrayState(desktop, vm);
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void ApplyTrayState(IClassicDesktopStyleApplicationLifetime desktop, MainWindowViewModel vm)
    {
        if (AppSettings.Current.EnableTrayIcon)
        {
            // Keep the process alive when the window is hidden to tray.
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _trayIconService ??= new TrayIconService(_window!, vm.StatusHero);
        }
        else
        {
            _trayIconService?.Dispose();
            _trayIconService = null;
            // Ensure the window is reachable as the main window before restoring
            // normal close-to-exit behaviour (relevant if we started hidden).
            if (desktop.MainWindow == null)
                desktop.MainWindow = _window;
            // Restore normal behaviour: closing the last window exits the process.
            desktop.ShutdownMode = ShutdownMode.OnLastWindowClose;
        }
    }
}
