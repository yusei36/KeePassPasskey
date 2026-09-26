// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Runtime.InteropServices;
using KeePass.Forms;
using KeePassPasskeyShared;

namespace KeePassPasskey.UI;

/// <summary>
/// Brings KeePass to the front while another application, usually the browser, has the foreground.
/// Windows refuses a background process the foreground and only flashes its taskbar button, so the
/// switch borrows the foreground thread's input state, the same approach KeePassRPC takes. With
/// KeePass in front, the dialogs it opens next (the key prompt, or the Windows Hello prompt of a
/// quick unlock plugin) receive the keyboard focus.
/// </summary>
internal static class KeePassForeground
{
	/// <summary>
	/// Shows the main window in front, restoring it from the tray or the taskbar, and returns the
	/// window that was in front before, or zero.
	/// </summary>
	internal static IntPtr BringToFront(MainForm mw)
	{
		IntPtr previous = GetForegroundWindow();
		uint foreThread = previous == IntPtr.Zero ? 0 : GetWindowThreadProcessId(previous, IntPtr.Zero);
		uint ownThread = GetCurrentThreadId();
		bool attached = foreThread != 0 && foreThread != ownThread && AttachThreadInput(foreThread, ownThread, true);

		// Restoring a locked workspace unlocks it by itself; the caller opens the prompt after the switch.
		mw.UIBlockAutoUnlock(true);
		try
		{
			mw.EnsureVisibleForegroundWindow(true, true);
			SetForegroundWindow(mw.Handle);
		}
		finally
		{
			mw.UIBlockAutoUnlock(false);
			if (attached) AttachThreadInput(foreThread, ownThread, false);
		}
		Log.Info($"attached={attached} inFront={GetForegroundWindow() == mw.Handle}");
		return previous;
	}

	/// <summary>Hands the foreground back, so the passkey prompt of the calling application continues in front.</summary>
	internal static void Restore(IntPtr previous)
	{
		if (previous != IntPtr.Zero && IsWindow(previous))
			SetForegroundWindow(previous);
	}

	#region Native methods

	[DllImport("user32.dll")]
	private static extern IntPtr GetForegroundWindow();

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool SetForegroundWindow(IntPtr hWnd);

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool IsWindow(IntPtr hWnd);

	[DllImport("user32.dll")]
	private static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);

	[DllImport("kernel32.dll")]
	private static extern uint GetCurrentThreadId();

	[DllImport("user32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

	#endregion
}
