// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
using Avalonia.Controls;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Prompts;

/// <summary>
/// Shows a prompt owned by the window that asked for the ceremony, usually the browser.
/// </summary>
/// <remarks>
/// The owner must be set before Show: afterwards the activation chain stays inconsistent and closing
/// the prompt promotes whatever is next in the z-order instead of the caller. SetForegroundWindow and
/// AttachThreadInput are deliberately not used; from a background process they are unreliable and
/// reshuffle other applications' z-order.
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

		// A process that has never received input is denied the foreground, so without this the first
		// prompt of a COM server opens behind the platform's ceremony UI.
		window.Topmost = true;

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
	}

	private static bool SetOwner(nint hwnd, nint ownerHwnd)
	{
		Marshal.SetLastSystemError(0);
		nint previous = Win32Native.SetWindowLongPtr(hwnd, Win32Native.GWLP_HWNDPARENT, ownerHwnd);
		if (previous != 0 || Marshal.GetLastWin32Error() == 0) return true;

		Log.Warn($"could not set prompt owner: error {Marshal.GetLastWin32Error()}", nameof(PromptActivation));
		return false;
	}
}
