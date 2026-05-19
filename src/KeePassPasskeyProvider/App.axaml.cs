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
            desktop.MainWindow = new MainWindow(vm);

            ApplyTrayState(desktop, vm);

            if (Program.StartHidden)
                desktop.MainWindow.Opened += static (s, _) => ((Avalonia.Controls.Window)s!).Hide();
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
            _trayIconService ??= new TrayIconService(desktop.MainWindow!, vm.StatusHero);
        }
        else
        {
            _trayIconService?.Dispose();
            _trayIconService = null;
            // Restore normal behaviour: closing the last window exits the process.
            desktop.ShutdownMode = ShutdownMode.OnLastWindowClose;
        }
    }
}
