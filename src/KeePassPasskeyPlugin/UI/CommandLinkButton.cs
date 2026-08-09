// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KeePassPasskey.UI;

/// <summary>
/// A Windows command link, which WinForms does not wrap. Needs FlatStyle.System, since the style
/// bit is only honoured by the native button.
/// </summary>
internal sealed class CommandLinkButton : Button
{
	private const int BS_COMMANDLINK = 0x0000000E;
	private const int BCM_SETNOTE = 0x1609;
	private const int BCM_GETIDEALSIZE = 0x1601;

	private string _note;

	internal CommandLinkButton()
	{
		FlatStyle = FlatStyle.System;
	}

	internal string Note
	{
		get { return _note; }
		set
		{
			_note = value;
			if (IsHandleCreated) ApplyNote();
		}
	}

	protected override CreateParams CreateParams
	{
		get
		{
			var cp = base.CreateParams;
			cp.Style |= BS_COMMANDLINK;
			return cp;
		}
	}

	protected override void OnHandleCreated(EventArgs e)
	{
		base.OnHandleCreated(e);
		ApplyNote();
		ApplyIdealHeight();
	}

	private void ApplyNote()
	{
		if (!string.IsNullOrEmpty(_note))
		{
			SendMessage(Handle, BCM_SETNOTE, IntPtr.Zero, _note);
			if (IsHandleCreated) ApplyIdealHeight();
		}
	}

	/// <summary>Asks the control how tall it wants to be at its current width, so the note decides
	/// the height instead of a guessed constant.</summary>
	private void ApplyIdealHeight()
	{
		var ideal = new SIZE { cx = Width };
		if (SendMessage(Handle, BCM_GETIDEALSIZE, IntPtr.Zero, ref ideal) != IntPtr.Zero && ideal.cy > 0)
			Height = ideal.cy;
	}

	private struct SIZE
	{
		internal int cx;
		internal int cy;
	}

	[DllImport("user32.dll", CharSet = CharSet.Unicode)]
	private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

	[DllImport("user32.dll")]
	private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, ref SIZE lParam);
}
