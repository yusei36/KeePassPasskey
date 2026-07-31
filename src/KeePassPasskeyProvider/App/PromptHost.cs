// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using KeePassPasskeyProvider.App.Prompts;
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using Microsoft.Win32;

namespace KeePassPasskeyProvider.App;

/// <summary>
/// Hosts Avalonia inside the COM server, whose own MTA message loop cannot run a UI, on a dedicated
/// STA thread that lives for the rest of the process.
/// </summary>
internal static class PromptHost
{
	private static readonly Lock _gate = new();
	private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(30);

	private static Thread? _uiThread;
	private static TaskCompletionSource? _ready;

	/// <summary>
	/// Windows runs a fresh COM server per ceremony and the UI stack takes seconds to come up, which
	/// the user would otherwise wait for.
	/// </summary>
	internal static void WarmUp()
	{
		var settings = KeePassPasskeySettings.Current;
		if (settings.UseLegacyNotificationPrompts)
		{
			Log.Debug("legacy notification prompts selected, not starting the UI host", nameof(PromptHost));
			return;
		}

		if (!settings.RegistrationVerification.HasFlag(UserVerificationMode.Notification)
			&& !settings.SignInVerification.HasFlag(UserVerificationMode.Notification))
		{
			Log.Debug("confirmation prompts disabled, not starting the UI host", nameof(PromptHost));
			return;
		}

		StartHost();
	}

	/// <summary>
	/// Shows a prompt on the Avalonia thread and blocks the calling (COM RPC) thread until it closes.
	/// </summary>
	/// <param name="factory">Creates the window; must complete the source it is handed when the window closes.</param>
	internal static TResult Show<TResult>(
		Func<TaskCompletionSource<TResult>, Window> factory,
		nint ownerHwnd,
		TResult cancelledResult,
		CancellationToken cancellation)
	{
		if (!EnsureStarted())
			return cancelledResult;

		var tcs = new TaskCompletionSource<TResult>(TaskCreationOptions.RunContinuationsAsynchronously);

		try
		{
			var built = Stopwatch.StartNew();
			var window = Dispatcher.UIThread.Invoke(() => factory(tcs));
			Log.Debug($"window built in {built.ElapsedMilliseconds} ms", nameof(PromptHost));

			// Posted before the cancellation registration so Show always runs before a Close.
			Dispatcher.UIThread.Post(() =>
			{
				try
				{
					PromptActivation.Show(window, ownerHwnd);
				}
				catch (Exception ex)
				{
					// Never leave the COM thread waiting on a window that failed to open.
					Log.Error($"could not show prompt: {ex.GetType().Name}: {ex.Message}", nameof(PromptHost));
					tcs.TrySetResult(cancelledResult);
				}
			});

			// A prompt behind the lock screen cannot be answered.
			void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
			{
				if (e.Reason == SessionSwitchReason.SessionLock)
					Dispatcher.UIThread.Post(window.Close);
			}

			SystemEvents.SessionSwitch += OnSessionSwitch;
			try
			{
				using (cancellation.Register(() => Dispatcher.UIThread.Post(window.Close)))
					return tcs.Task.GetAwaiter().GetResult();
			}
			finally
			{
				SystemEvents.SessionSwitch -= OnSessionSwitch;
			}
		}
		catch (Exception ex)
		{
			Log.Error($"prompt failed: {ex.GetType().Name}: {ex.Message}", nameof(PromptHost));
			return cancelledResult;
		}
	}

	private static void PrewarmPromptWindow()
	{
		var warmed = Stopwatch.StartNew();
		try
		{
			var window = new RegistrationPromptWindow(
				new RegistrationPromptViewModel(string.Empty, string.Empty, string.Empty, [], []));
			window.Close();
			Log.Debug($"prompt window prewarmed in {warmed.ElapsedMilliseconds} ms", nameof(PromptHost));
		}
		catch (Exception ex)
		{
			// Only an optimisation; the real prompt builds its own window either way.
			Log.Debug($"prompt prewarm failed: {ex.GetType().Name}: {ex.Message}", nameof(PromptHost));
		}
	}

	private static bool EnsureStarted()
	{
		var waited = Stopwatch.StartNew();
		var ready = StartHost();

		try
		{
			if (ready.Task.Wait(StartupTimeout))
			{
				Log.Debug($"UI host ready after {waited.ElapsedMilliseconds} ms", nameof(PromptHost));
				return true;
			}

			Log.Error($"UI host did not start within {StartupTimeout.TotalSeconds}s", nameof(PromptHost));
			return false;
		}
		catch (Exception ex)
		{
			Log.Error($"UI host start failed: {ex.GetType().Name}: {ex.Message}", nameof(PromptHost));
			return false;
		}
	}

	private static TaskCompletionSource StartHost()
	{
		lock (_gate)
		{
			if (_ready != null) return _ready;

			var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
			_ready = ready;

			_uiThread = new Thread(() =>
			{
				try
				{
					// No application lifetime: nothing may shut the framework down between ceremonies,
					// and the prompts have no main window to be the last one closed.
					AppBuilder.Configure<PromptApplication>()
						.UsePlatformDetect()
						.LogToTrace()
						.SetupWithoutStarting();

					ready.TrySetResult();
					Dispatcher.UIThread.Post(PrewarmPromptWindow, DispatcherPriority.Background);
					Dispatcher.UIThread.MainLoop(CancellationToken.None);
					Log.Info("Avalonia dispatcher exited", nameof(PromptHost));
				}
				catch (Exception ex)
				{
					Log.Error($"Avalonia host failed: {ex.GetType().Name}: {ex.Message}", nameof(PromptHost));
					ready.TrySetException(ex);
				}
			})
			{
				IsBackground = true,
				Name = "PasskeyPromptHost",
			};
			_uiThread.SetApartmentState(ApartmentState.STA);
			_uiThread.Start();
			Log.Info("starting Avalonia prompt host", nameof(PromptHost));

			return ready;
		}
	}
}
