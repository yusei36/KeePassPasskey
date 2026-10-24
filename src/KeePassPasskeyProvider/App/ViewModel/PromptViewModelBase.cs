// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>
/// Shared prompt behaviour: the countdown that auto-cancels the ceremony (same budget the toasts
/// used) and the confirm/cancel result the window reports back.
/// </summary>
public abstract partial class PromptViewModelBase : ObservableObject, IDisposable
{
	private readonly DispatcherTimer _timer;
	private readonly int _totalSeconds;
	private int _remainingSeconds;

	[ObservableProperty] public partial string WindowTitle { get; set; } = "";
	[ObservableProperty] public partial string SiteHeadline { get; set; } = "";
	[ObservableProperty] public partial string SiteSubhead { get; set; } = "";
	[ObservableProperty] public partial bool HasSiteSubhead { get; set; }
	[ObservableProperty] public partial string SiteLetter { get; set; } = "?";
	[ObservableProperty] public partial IBrush SiteTileBrush { get; set; } = Brushes.Gray;
	[ObservableProperty] public partial double CountdownValue { get; set; } = 100;
	[ObservableProperty] public partial string CountdownText { get; set; } = "";
	[ObservableProperty] public partial string ConfirmText { get; set; } = "OK";

	/// <summary>True once the user confirmed; false for cancel, close and timeout alike.</summary>
	public bool Approved { get; private set; }

	public event EventHandler? CloseRequested;

	protected PromptViewModelBase()
	{
		_totalSeconds = Math.Max(1, KeePassPasskeySettings.Current.NotificationVerificationTimeoutMilliseconds / 1000);
		_remainingSeconds = _totalSeconds;
		UpdateCountdown();

		_timer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Normal, OnTick);
	}

	public abstract bool CanConfirm { get; }

	/// <summary>Started once the window is on screen, so building it does not eat into the budget.</summary>
	internal void StartCountdown()
	{
		if (!_timer.IsEnabled) _timer.Start();
	}

	protected void SetSite(string headline, string subhead, string tileSource)
	{
		SiteHeadline = headline;
		SiteSubhead = subhead;
		HasSiteSubhead = subhead.Length > 0;
		SiteLetter = LetterTile.Letter(tileSource);
		SiteTileBrush = LetterTile.Brush(tileSource);
	}

	[RelayCommand]
	private void Confirm()
	{
		if (!CanConfirm) return;
		Approved = true;
		CloseRequested?.Invoke(this, EventArgs.Empty);
	}

	[RelayCommand]
	private void Cancel() => CloseRequested?.Invoke(this, EventArgs.Empty);

	private void OnTick(object? sender, EventArgs e)
	{
		_remainingSeconds--;
		UpdateCountdown();

		if (_remainingSeconds > 0) return;

		_timer.Stop();
		CloseRequested?.Invoke(this, EventArgs.Empty);
	}

	private void UpdateCountdown()
	{
		int remaining = Math.Max(0, _remainingSeconds);
		CountdownValue = (double)remaining / _totalSeconds * 100;
		CountdownText = $"{remaining / 60}:{remaining % 60:00}";
	}

	public void Dispose()
	{
		_timer.Stop();
		GC.SuppressFinalize(this);
	}
}
