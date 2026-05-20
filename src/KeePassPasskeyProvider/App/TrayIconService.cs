// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App;

internal sealed class TrayIconService : IDisposable
{
    // Named event used to signal the running instance to show its window.
    // A second launch calls OpenEvent + SetEvent; this service watches for it.
    internal const string ShowEventName = "Local\\KeePassPasskeyProvider_Show";

    // SystemFillColorSuccess (light), SystemFillColorCaution (dark), SystemFillColorCritical (light)
    private static readonly Color StatusColorSuccess = Color.FromRgb(0x0F, 0x7B, 0x0F);
    private static readonly Color StatusColorCaution = Color.FromRgb(0xFC, 0xE1, 0x00);
    private static readonly Color StatusColorCritical = Color.FromRgb(0xC4, 0x2B, 0x1C);

    private readonly StatusHeroViewModel _statusHero;
    private readonly Window _window;
    private TrayIcon? _trayIcon;
    private volatile bool _disposed;
    private static Bitmap? _baseIcon;

    // The event handle is owned by WatchShowEvent after Dispose() is called.
    private nint _showEvent;

    internal TrayIconService(Window window, StatusHeroViewModel statusHero)
    {
        _window     = window;
        _statusHero = statusHero;

        _showEvent = Win32Native.CreateEvent(0, false, false, ShowEventName);
        _ = Task.Run(WatchShowEvent);

        _statusHero.PropertyChanged += OnStatusChanged;
        CreateTrayIcon();
    }

    private void CreateTrayIcon()
    {
        _trayIcon = new TrayIcon
        {
            ToolTipText = GetTooltip(_statusHero.Status),
            Icon        = BuildIcon(_statusHero.Status),
            Menu        = BuildContextMenu(),
        };
        _trayIcon.Clicked += (_, _) => Dispatcher.UIThread.Post(ShowWindow);
    }

    internal void ShowWindow()
    {
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
        (_window as MainWindow)?.NavigateToHome();
    }

    private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(StatusHeroViewModel.Status) || _trayIcon == null) return;
        UpdateIcon();
    }

    private void UpdateIcon()
    {
        if (_trayIcon == null) return;
        _trayIcon.Icon        = BuildIcon(_statusHero.Status);
        _trayIcon.ToolTipText = GetTooltip(_statusHero.Status);
    }

    private async Task WatchShowEvent()
    {
        while (true)
        {
            uint r = Win32Native.WaitForSingleObject(_showEvent, Win32Native.INFINITE);
            if (_disposed)
            {
                // We own the handle now; close it and exit.
                Win32Native.CloseHandle(_showEvent);
                return;
            }
            if (r == Win32Native.WAIT_OBJECT_0)
                await Dispatcher.UIThread.InvokeAsync(ShowWindow);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _statusHero.PropertyChanged -= OnStatusChanged;
        _trayIcon?.Dispose();
        _trayIcon = null;
        // Transfer handle ownership to WatchShowEvent (it will close it after waking).
        nint ev = _showEvent;
        _showEvent = 0;
        if (ev != 0)
            Win32Native.SetEvent(ev);
    }

    private static WindowIcon BuildIcon(ProviderStatus status)
    {
        var dotColor = status switch
        {
            ProviderStatus.Ready
                => StatusColorSuccess,
            ProviderStatus.KeePassNotConnected or ProviderStatus.NoDatabase or ProviderStatus.WaitingToBeEnabled
                => StatusColorCaution,
            _ => StatusColorCritical,
        };

        _baseIcon ??= new Bitmap(AssetLoader.Open(
            new Uri("avares://KeePassPasskeyProvider/Resources/app-icon.png")));

        const int size = 32;
        var rtb = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
        using (var ctx = rtb.CreateDrawingContext())
        {
            ctx.DrawImage(_baseIcon, new Rect(0, 0, size, size));
            // White halo so the dot is visible against any icon colour
            ctx.DrawEllipse(new SolidColorBrush(Colors.White), null, new Point(26, 26), 6, 6);
            ctx.DrawEllipse(new SolidColorBrush(dotColor),     null, new Point(26, 26), 5, 5);
        }

        using var ms = new MemoryStream();
        rtb.Save(ms);
        ms.Position = 0;
        return new WindowIcon(ms);
    }

    private static string GetTooltip(ProviderStatus status) => status switch
    {
        ProviderStatus.Ready              => "Ready",
        ProviderStatus.KeePassNotConnected   => "KeePass not connected",
        ProviderStatus.NoDatabase         => "No database open",
        ProviderStatus.WaitingToBeEnabled => "Waiting to be enabled",
        ProviderStatus.VersionMismatch    => "Version mismatch",
        ProviderStatus.NotRegistered      => "Not registered",
        ProviderStatus.AutoregisterFailed => "Registration failed",
        _                                 => status.ToString(),
    };

    private NativeMenu BuildContextMenu()
    {
        var open = new NativeMenuItem("Open KeePassPasskey");
        open.Click += (_, _) => Dispatcher.UIThread.Post(ShowWindow);

        var exit = new NativeMenuItem("Exit");
        exit.Click += (_, _) =>
        {
            if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
                d.Shutdown();
        };

        return new NativeMenu { open, new NativeMenuItemSeparator(), exit };
    }
}
