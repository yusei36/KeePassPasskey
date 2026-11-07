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

	// SystemFillColorSuccess (light), SystemFillColorCaution (dark), SystemFillColorCritical (light)
	private static readonly Color StatusColorSuccess = Color.FromRgb(0x0F, 0x7B, 0x0F);
	private static readonly Color StatusColorCaution = Color.FromRgb(0xFC, 0xE1, 0x00);
	private static readonly Color StatusColorCritical = Color.FromRgb(0xC4, 0x2B, 0x1C);

	private readonly StatusHeroViewModel _statusHero;
	private readonly Window _window;
	private TrayIcon? _trayIcon;
	private volatile bool _disposed;
	private static Bitmap? _baseIcon;
	private DateTime _lastClickTime;
	private ProviderStatus? _lastRenderedStatus;

	internal TrayIconService(Window window, StatusHeroViewModel statusHero)
	{
		_window = window;
		_statusHero = statusHero;

		_statusHero.PropertyChanged += OnStatusChanged;
		AppLanguage.Changed += OnLanguageChanged;
		CreateTrayIcon();
	}

	private void OnLanguageChanged(object? sender, EventArgs e)
	{
		if (_trayIcon == null) return;
		_trayIcon.Menu = BuildContextMenu();
		_trayIcon.ToolTipText = GetTooltip(_statusHero.Status);
	}

	private void CreateTrayIcon()
	{
		_trayIcon = new TrayIcon
		{
			ToolTipText = GetTooltip(_statusHero.Status),
			Icon = BuildIcon(_statusHero.Status),
			Menu = BuildContextMenu(),
		};
		_lastRenderedStatus = _statusHero.Status;
		// Since Avalonia 12.1 a TrayIcon only creates its native icon once attached to the Application
		if (Avalonia.Application.Current is { } app)
			TrayIcon.SetIcons(app, [_trayIcon]);
		_trayIcon.Clicked += (_, _) =>
		{
			var now = DateTime.UtcNow;
			bool isDoubleClick = (now - _lastClickTime).TotalMilliseconds <= Win32Native.GetDoubleClickTime();
			_lastClickTime = now;
			if (isDoubleClick)
				Dispatcher.UIThread.Post(ShowWindow);
		};
	}

	internal void ShowWindow() => (_window as MainWindow)?.ShowOnPage(settings: false);

	private void ShowSettings() => (_window as MainWindow)?.ShowOnPage(settings: true);

	private void OnStatusChanged(object? sender, PropertyChangedEventArgs e)
	{
		if (e.PropertyName != nameof(StatusHeroViewModel.Status) || _trayIcon == null) return;
		UpdateIcon();
	}

	private void UpdateIcon()
	{
		if (_trayIcon == null) return;
		var status = _statusHero.Status;
		if (_lastRenderedStatus == status) return;
		_lastRenderedStatus = status;

		var previousIcon = _trayIcon.Icon;
		_trayIcon.Icon = BuildIcon(status);
		_trayIcon.ToolTipText = GetTooltip(status);
		(previousIcon as IDisposable)?.Dispose();
	}

	public void Dispose()
	{
		if (_disposed) return;
		_disposed = true;
		_statusHero.PropertyChanged -= OnStatusChanged;
		AppLanguage.Changed -= OnLanguageChanged;
		if (Avalonia.Application.Current is { } app)
			TrayIcon.SetIcons(app, null);
		_trayIcon?.Dispose();
		_trayIcon = null;
	}

	private static WindowIcon BuildIcon(ProviderStatus status)
	{
		var dotColor = status switch
		{
			ProviderStatus.Ready
				=> StatusColorSuccess,
			ProviderStatus.KeePassNotConnected or ProviderStatus.NoDatabase or ProviderStatus.WaitingToBeEnabled or ProviderStatus.VersionMismatch
				=> StatusColorCaution,
			_ => StatusColorCritical,
		};

		_baseIcon ??= new Bitmap(AssetLoader.Open(
			new Uri("avares://KeePassPasskeyProvider/Resources/app-icon.png")));

		const int size = 32;
		using var rtb = new RenderTargetBitmap(new PixelSize(size, size), new Vector(96, 96));
		using (var ctx = rtb.CreateDrawingContext())
		{
			ctx.DrawImage(_baseIcon, new Rect(0, 0, size, size));
			// White halo so the dot is visible against any icon colour
			ctx.DrawEllipse(new SolidColorBrush(Colors.White), null, new Point(26, 26), 6, 6);
			ctx.DrawEllipse(new SolidColorBrush(dotColor), null, new Point(26, 26), 5, 5);
		}

		using var ms = new MemoryStream();
		rtb.Save(ms, PngBitmapEncoderOptions.Default);
		ms.Position = 0;
		return new WindowIcon(ms);
	}

	private static string GetTooltip(ProviderStatus status) => status switch
	{
		ProviderStatus.Ready => Strings.Tray_Tooltip_Ready,
		ProviderStatus.KeePassNotConnected => Strings.Common_Status_KeePassNotConnected,
		ProviderStatus.NoDatabase => Strings.Common_Status_NoDatabase,
		ProviderStatus.WaitingToBeEnabled => Strings.Common_Status_WaitingToBeEnabled,
		ProviderStatus.IncompatibleVersion => Strings.Common_Status_IncompatibleVersion,
		ProviderStatus.VersionMismatch => Strings.Common_Status_VersionMismatch,
		ProviderStatus.NotRegistered => Strings.Common_Status_NotRegistered,
		ProviderStatus.AutoregisterFailed => Strings.Tray_Tooltip_RegistrationFailed,
		_ => status.ToString(),
	};

	private NativeMenu BuildContextMenu()
	{
		var open = new NativeMenuItem(Strings.Tray_Menu_Open);
		open.Click += (_, _) => Dispatcher.UIThread.Post(ShowWindow);

		var settings = new NativeMenuItem(Strings.Tray_Menu_Settings);
		settings.Click += (_, _) => Dispatcher.UIThread.Post(ShowSettings);

		var exit = new NativeMenuItem(Strings.Tray_Menu_Exit);
		exit.Click += (_, _) =>
		{
			if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d)
				d.Shutdown();
		};

		return new NativeMenu { open, settings, new NativeMenuItemSeparator(), exit };
	}
}
