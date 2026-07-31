// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Prompts;

/// <summary>
/// Shows a prompt owned by the window that asked for the ceremony, usually the browser.
/// </summary>
/// <remarks>
/// The owner must be set before Show: afterwards the activation chain stays inconsistent and closing
/// the prompt promotes an arbitrary window instead of the caller.
/// </remarks>
internal static class PromptActivation
{
	internal static void Show(Window window, nint ownerHwnd)
	{
		bool ownerValid = ownerHwnd != 0 && Win32Native.IsWindow(ownerHwnd);
		if (!ownerValid && ownerHwnd != 0)
			Log.Warn($"caller window 0x{ownerHwnd:X} is gone, showing unowned", nameof(PromptActivation));

		// Avalonia creates the native window with the Window object, so the handle already exists.
		nint hwnd = window.TryGetPlatformHandle()?.Handle ?? 0;
		bool ownerSet = ownerValid && hwnd != 0 && SetOwner(hwnd, ownerHwnd);

		// Restores the rounded frame the undecorated window loses. No-op before Windows 11.
		if (hwnd != 0)
		{
			int cornerPreference = Win32Native.DWMWCP_ROUND;
			_ = Win32Native.DwmSetWindowAttribute(
				hwnd, Win32Native.DWMWA_WINDOW_CORNER_PREFERENCE, in cornerPreference, sizeof(int));
		}

		// Keeps the prompt visible even when the foreground handoff below does not apply.
		window.Topmost = true;

		SeedScreen(window, ownerValid ? ownerHwnd : 0);

		var shown = Stopwatch.StartNew();
		window.Show();

		if (hwnd == 0)
			hwnd = window.TryGetPlatformHandle()?.Handle ?? 0;

		if (!ownerSet && ownerValid && hwnd != 0)
		{
			Log.Warn("no window handle before Show, setting owner late", nameof(PromptActivation));
			SetOwner(hwnd, ownerHwnd);
		}

		bool foreground = hwnd != 0 && Win32Native.GetForegroundWindow() == hwnd;
		Log.Debug(
			$"window shown in {shown.ElapsedMilliseconds} ms (ownerSet={ownerSet} foreground={foreground})",
			nameof(PromptActivation));

		if (!foreground && hwnd != 0 && ownerValid && TryTakeForeground(hwnd, ownerHwnd))
			RestoreForegroundOnClose(window, hwnd, ownerHwnd);
	}

	/// <summary>
	/// CenterScreen centres on the screen holding the window's position, which starts at the primary
	/// monitor's origin. Seeding it puts the prompt on the caller's monitor instead.
	/// </summary>
	private static void SeedScreen(Window window, nint ownerHwnd)
	{
		nint monitor = ownerHwnd != 0
			? Win32Native.MonitorFromWindow(ownerHwnd, Win32Native.MONITOR_DEFAULTTONEAREST)
			: 0;

		if (monitor != 0)
		{
			var info = new Win32Native.MONITORINFO { cbSize = Marshal.SizeOf<Win32Native.MONITORINFO>() };
			if (Win32Native.GetMonitorInfo(monitor, ref info))
			{
				window.Position = new PixelPoint(
					(info.rcWork.Left + info.rcWork.Right) / 2,
					(info.rcWork.Top + info.rcWork.Bottom) / 2);
				return;
			}
		}

		// No usable caller window, so fall back to wherever the user's pointer is.
		if (Win32Native.GetCursorPos(out Win32Native.POINT cursor))
			window.Position = new PixelPoint(cursor.X, cursor.Y);
	}

	/// <summary>
	/// Closing, not Closed: once the window is destroyed the process no longer owns the foreground and
	/// the system promotes an arbitrary window.
	/// </summary>
	private static void RestoreForegroundOnClose(Window window, nint hwnd, nint ownerHwnd)
	{
		window.Closing += (_, _) =>
		{
			if (Win32Native.GetForegroundWindow() != hwnd || !Win32Native.IsWindow(ownerHwnd)) return;

			bool restored = Win32Native.SetForegroundWindow(ownerHwnd);
			Log.Debug($"returning foreground to {Describe(ownerHwnd)}: {restored}", nameof(PromptActivation));
		};
	}

	/// <summary>
	/// A COM server is refused the foreground (the platform never calls CoAllowSetForegroundWindow), so
	/// the prompt opens unfocused and ignores Enter and Escape. Only when the owner is in front, so the
	/// focus always comes from the window that asked for the passkey.
	/// </summary>
	private static bool TryTakeForeground(nint hwnd, nint ownerHwnd)
	{
		nint foregroundHwnd = Win32Native.GetForegroundWindow();
		if (foregroundHwnd != ownerHwnd)
		{
			Log.Debug($"foreground is {Describe(foregroundHwnd)}, not the ceremony owner; leaving it alone", nameof(PromptActivation));
			return false;
		}

		uint ownerThread = Win32Native.GetWindowThreadProcessId(ownerHwnd, out _);
		uint ourThread = Win32Native.GetCurrentThreadId();
		if (ownerThread == 0 || ownerThread == ourThread) return false;

		bool attached = Win32Native.AttachThreadInput(ourThread, ownerThread, true);
		try
		{
			_ = Win32Native.SetForegroundWindow(hwnd);
		}
		finally
		{
			if (attached) _ = Win32Native.AttachThreadInput(ourThread, ownerThread, false);
		}

		bool ours = Win32Native.GetForegroundWindow() == hwnd;
		Log.Info($"foreground handoff from {Describe(ownerHwnd)}: attached={attached} ours={ours}", nameof(PromptActivation));
		return ours;
	}

	private static string Describe(nint hwnd)
	{
		if (hwnd == 0) return "none";
		_ = Win32Native.GetWindowThreadProcessId(hwnd, out uint pid);
		string name;
		try { name = Process.GetProcessById((int)pid).ProcessName; }
		catch { name = "?"; }
		return $"0x{hwnd:X}/{name}({pid})";
	}

	private static bool SetOwner(nint hwnd, nint ownerHwnd)
	{
		// 0 comes back both on failure and when there was no previous owner, so only the error tells.
		Marshal.SetLastSystemError(0);
		nint previous = Win32Native.SetWindowLongPtr(hwnd, Win32Native.GWLP_HWNDPARENT, ownerHwnd);
		if (previous != 0 || Marshal.GetLastWin32Error() == 0) return true;

		Log.Warn($"could not set prompt owner: error {Marshal.GetLastWin32Error()}", nameof(PromptActivation));
		return false;
	}
}
