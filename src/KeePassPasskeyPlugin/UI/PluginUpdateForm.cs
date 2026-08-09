// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KeePassPasskey.Update;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.UI;

/// <summary>
/// Offers the plugin update, runs it, and then offers the restart in place of the first step.
/// A cancelled or failed install swaps in a third step instead of closing, so every outcome is
/// answered in the dialog the user is already looking at.
/// </summary>
internal sealed class PluginUpdateForm : Form
{
	private const int ContentWidth = 420;
	// Only until the handle exists and the control reports the height its note actually needs.
	private const int LinkHeight = 56;
	private const int DetailRowHeight = 16;

	private readonly PluginUpdateInfo _info;
	private readonly Func<PluginInstallOutcome> _install;
	private readonly ToolTip _toolTip = new ToolTip();

	private readonly Panel _root;
	private readonly Panel _updateStep;
	private readonly Panel _restartStep;
	private Panel _failureStep;
	private Panel _currentStep;

	private CommandLinkButton _updateNow;
	private CommandLinkButton _updateLater;
	private CommandLinkButton _restartNow;
	private CommandLinkButton _restartLater;
	private CommandLinkButton _retry;
	private CommandLinkButton _failureLater;
	private Label _failureText;
	private Icon _icon;

	internal PluginUpdateChoice Choice { get; private set; } = PluginUpdateChoice.Later;
	internal bool RestartRequested { get; private set; }
	internal PluginInstallOutcome InstallOutcome { get; private set; }

	internal PluginUpdateForm(PluginUpdateInfo info, Func<PluginInstallOutcome> install)
	{
		_info = info;
		_install = install;

		AutoScaleMode = AutoScaleMode.Font;
		Font = SystemFonts.MessageBoxFont;
		Text = "KeePassPasskey plugin update";
		// FixedDialog suppresses the title bar icon, the one piece of identity a native dialog gets.
		FormBorderStyle = FormBorderStyle.FixedSingle;
		MaximizeBox = false;
		MinimizeBox = false;
		ShowInTaskbar = false;
		StartPosition = FormStartPosition.CenterParent;
		AutoSize = true;
		AutoSizeMode = AutoSizeMode.GrowAndShrink;
		ApplyIcon();

		_root = new Panel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			Dock = DockStyle.Fill,
			Padding = new Padding(14),
		};

		_updateStep = BuildUpdateStep();
		_restartStep = BuildRestartStep();

		Controls.Add(_root);
		ShowStep(_updateStep, _updateNow, _updateLater);
	}

	private Panel BuildUpdateStep()
	{
		var panel = StepPanel();

		panel.Controls.Add(Heading(string.Format(
			"Version {0} is available. Version {1} is installed.",
			Short(_info.AvailableVersion), Short(_info.InstalledVersion))));
		panel.Controls.Add(Body("Creating and using passkeys can stop working until these match.",
			SystemColors.GrayText));

		panel.Controls.Add(BuildDetails());

		_updateNow = Link("Update now", "Installs the update. Restarting to load it is a separate step.", RunInstall);
		_updateLater = Link("Later", "Ask again at the next KeePass start", () => Finish(PluginUpdateChoice.Later));
		panel.Controls.Add(_updateNow);
		panel.Controls.Add(_updateLater);

		panel.Controls.Add(Separator());
		panel.Controls.Add(SecondaryLink("Skip version " + Short(_info.AvailableVersion),
			"ask again when a newer version arrives",
			() => Finish(PluginUpdateChoice.SkipThisVersion)));
		panel.Controls.Add(SecondaryLink("Never check for plugin updates",
			"can be re-enabled in the app's settings",
			() => Finish(PluginUpdateChoice.NeverCheck)));

		return panel;
	}

	private Panel BuildRestartStep()
	{
		var panel = StepPanel();

		panel.Controls.Add(Heading("The plugin was updated to " + Short(_info.AvailableVersion) + "."));
		panel.Controls.Add(Body("KeePass has to restart before the new version is loaded.", SystemColors.ControlText));

		_restartNow = Link("Restart now", "KeePass closes and reopens", () =>
		{
			RestartRequested = true;
			Finish(PluginUpdateChoice.Update);
		});
		_restartLater = Link("Later", "Sign-in keeps using " + Short(_info.InstalledVersion)
			+ " until KeePass restarts", () => Finish(PluginUpdateChoice.Update));
		panel.Controls.Add(_restartNow);
		panel.Controls.Add(_restartLater);

		return panel;
	}

	private Panel BuildFailureStep()
	{
		var panel = StepPanel();

		panel.Controls.Add(Heading("The plugin was not updated."));
		_failureText = new Label
		{
			AutoSize = true,
			Margin = new Padding(3, 0, 3, 14),
			MaximumSize = new Size(ContentWidth, 0),
		};
		panel.Controls.Add(_failureText);

		_retry = Link("Try again", "", RunInstall);
		_failureLater = Link("Later", "Ask again at the next KeePass start",
			() => Finish(PluginUpdateChoice.Later));
		panel.Controls.Add(_retry);
		panel.Controls.Add(_failureLater);

		return panel;
	}

	private Control BuildDetails()
	{
		var details = new TableLayoutPanel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			ColumnCount = 2,
			Margin = new Padding(3, 6, 3, 14),
		};
		details.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		details.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

		details.Controls.Add(Caption("From"), 0, 0);
		details.Controls.Add(
			ValueLabel("KeePassPasskey (" + _info.ChannelDisplayName + ")", SystemColors.ControlText), 1, 0);

		// Empty spacer, sized down so it does not set the caption column's width.
		details.Controls.Add(new Label { AutoSize = false, Margin = new Padding(0), Size = Size.Empty }, 0, 1);
		details.Controls.Add(PathLabel(_info.PackagePath, SystemColors.GrayText), 1, 1);

		details.Controls.Add(Caption("To"), 0, 2);
		details.Controls.Add(PathLabel(_info.TargetDirectory, SystemColors.ControlText), 1, 2);

		return details;
	}

	/// <summary>Separates the two ways of not updating from the two real choices above them.</summary>
	private static Control Separator() => new Panel
	{
		BackColor = SystemColors.ControlLight,
		Height = 1,
		Margin = new Padding(3, 12, 3, 10),
		Width = ContentWidth,
	};

	private static FlowLayoutPanel StepPanel() => new FlowLayoutPanel
	{
		AutoSize = true,
		AutoSizeMode = AutoSizeMode.GrowAndShrink,
		FlowDirection = FlowDirection.TopDown,
		WrapContents = false,
	};

	// Fixed height rather than auto-sized: an auto-sized caption is taller than the value beside it
	// and would space its own row wider than the rest.
	private static Label Caption(string text) => new Label
	{
		AutoSize = false,
		ForeColor = SystemColors.GrayText,
		Margin = new Padding(3, 0, 14, 0),
		Size = new Size(TextRenderer.MeasureText(text, SystemFonts.MessageBoxFont).Width, DetailRowHeight),
		Text = text,
	};

	private static Label ValueLabel(string text, Color color) => new Label
	{
		AutoEllipsis = true,
		AutoSize = false,
		ForeColor = color,
		Size = new Size(ContentWidth - 55, DetailRowHeight),
		Text = text ?? "",
	};

	private Label PathLabel(string path, Color color)
	{
		var label = ValueLabel(path, color);
		_toolTip.SetToolTip(label, path ?? "");
		return label;
	}

	// Sized to the text it measures rather than auto-sized: an auto-sized label at this size carries
	// enough leading below the glyphs to detach the heading from the hint under it.
	private static Label Heading(string text)
	{
		var font = new Font(SystemFonts.MessageBoxFont.FontFamily, SystemFonts.MessageBoxFont.Size + 3f);
		var measured = TextRenderer.MeasureText(text, font, new Size(ContentWidth, 0), TextFormatFlags.WordBreak);
		return new Label
		{
			AutoSize = false,
			Font = font,
			Margin = new Padding(3, 0, 3, 2),
			Size = new Size(ContentWidth, measured.Height),
			Text = text,
		};
	}

	private static Label Body(string text, Color color) => new Label
	{
		AutoSize = true,
		ForeColor = color,
		Margin = new Padding(3, 0, 3, 12),
		MaximumSize = new Size(ContentWidth, 0),
		Text = text,
	};

	private CommandLinkButton Link(string text, string note, Action onClick)
	{
		var button = new CommandLinkButton
		{
			Note = note,
			Size = new Size(ContentWidth, LinkHeight),
			Text = text,
		};
		button.Click += (s, e) => onClick();
		return button;
	}

	private LinkLabel SecondaryLink(string text, string note, Action onClick)
	{
		var label = new LinkLabel
		{
			AutoSize = true,
			LinkArea = new LinkArea(0, text.Length),
			Margin = new Padding(3, 0, 3, 0),
			MaximumSize = new Size(ContentWidth, 0),
			Text = text + " (" + note + ")",
		};
		label.LinkClicked += (s, e) => onClick();
		return label;
	}

	private void RunInstall()
	{
		SetBusy(true);
		try
		{
			InstallOutcome = _install();
		}
		finally
		{
			SetBusy(false);
		}

		if (InstallOutcome.Success)
			ShowRestartStep();
		else
			ShowFailureStep();
	}

	private void ShowRestartStep()
	{
		Choice = PluginUpdateChoice.Update;
		ShowStep(_restartStep, _restartNow, _restartLater);
	}

	// A dismissed elevation prompt is a decision rather than an error, so it only reports what it
	// left behind. Anything else carries the reason the write failed.
	private void ShowFailureStep()
	{
		if (_failureStep == null)
			_failureStep = BuildFailureStep();

		_failureText.Text = InstallOutcome.Cancelled
			? "Permission was not granted, so version " + Short(_info.InstalledVersion) + " is still in use."
			: InstallOutcome.Error ?? "The plugin file could not be written.";
		_retry.Note = InstallOutcome.Cancelled ? "Asks for permission once more" : "Runs the update again";

		ShowStep(_failureStep, _retry, _failureLater);
	}

	private void ShowStep(Panel step, IButtonControl accept, IButtonControl cancel)
	{
		if (_currentStep == step) return;

		if (_currentStep != null)
		{
			// Pin the width so swapping to a shorter step only changes the height.
			MinimumSize = new Size(Width, 0);
			_root.Controls.Remove(_currentStep);
		}

		_currentStep = step;
		_root.Controls.Add(step);
		AcceptButton = accept;
		CancelButton = cancel;
	}

	private void SetBusy(bool busy)
	{
		_currentStep.Enabled = !busy;
		Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
		Update();
	}

	private void Finish(PluginUpdateChoice choice)
	{
		Choice = choice;
		DialogResult = DialogResult.OK;
	}

	private void ApplyIcon()
	{
		try
		{
			using (var bitmap = new Bitmap(KeePassPasskeyExt.PluginImage))
			{
				IntPtr handle = bitmap.GetHicon();
				try { _icon = (Icon)Icon.FromHandle(handle).Clone(); }
				finally { DestroyIcon(handle); }
			}
			Icon = _icon;
		}
		catch { ShowIcon = false; }
	}

	private static string Short(string version) => PipeConstants.StripBuildMetadata(version);

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_toolTip.Dispose();
			// Steps swapped out of the tree are not reachable from the form any more.
			_updateStep?.Dispose();
			_restartStep?.Dispose();
			_failureStep?.Dispose();
			_icon?.Dispose();
		}
		base.Dispose(disposing);
	}

	[DllImport("user32.dll")]
	private static extern bool DestroyIcon(IntPtr handle);
}
