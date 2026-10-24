// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>
/// DWM window attributes Avalonia does not expose.
/// </summary>
internal static class WindowChrome
{
	/// <summary>How long a window stays cloaked after opening, long enough for the render thread to
	/// have a frame up. A dispatcher post is a frame too early, rendering not being on that thread.</summary>
	internal static readonly TimeSpan UncloakDelay = TimeSpan.FromMilliseconds(120);

	/// <summary>
	/// Cloaked until there is something to show: DWM composites the window before Avalonia paints it,
	/// which is what makes an empty frame and its shadow appear first.
	/// </summary>
	internal static void SetCloaked(Window window, bool cloaked)
		=> Set(window, Win32Native.DWMWA_CLOAK, cloaked ? 1u : 0u);

	/// <summary>Windows 11 draws the border in the accent colour.</summary>
	internal static void RemoveBorder(Window window)
		=> Set(window, Win32Native.DWMWA_BORDER_COLOR, Win32Native.DWMWA_COLOR_NONE);

	private static void Set(Window window, uint attribute, uint value)
	{
		nint hwnd = window.TryGetPlatformHandle()?.Handle ?? 0;
		if (hwnd == 0) return;

		_ = Win32Native.DwmSetWindowAttribute(hwnd, attribute, value, sizeof(uint));
	}
}
