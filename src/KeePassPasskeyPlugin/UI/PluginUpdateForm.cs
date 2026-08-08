// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Drawing;
using System.Windows.Forms;
using KeePassPasskey.Update;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.UI;

/// <summary>
/// Offers the plugin update, runs it, and then offers the restart in place of the first step.
/// The install runs from here so both steps stay in one dialog.
/// </summary>
internal sealed class PluginUpdateForm : Form
{
	private const int ContentWidth = 520;
	private const int LinkHeight = 58;

	private readonly PluginUpdateInfo _info;
	private readonly Func<PluginInstallOutcome> _install;
	private readonly ToolTip _toolTip = new ToolTip();

	private readonly Panel _root;
	private readonly Panel _updateStep;
	private readonly Panel _restartStep;
	private CommandLinkButton _restartLater;

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
		FormBorderStyle = FormBorderStyle.FixedDialog;
		MaximizeBox = false;
		MinimizeBox = false;
		ShowInTaskbar = false;
		StartPosition = FormStartPosition.CenterParent;
		AutoSize = true;
		AutoSizeMode = AutoSizeMode.GrowAndShrink;

		_root = new Panel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			Dock = DockStyle.Fill,
			Padding = new Padding(14),
		};

		_updateStep = BuildUpdateStep();
		_restartStep = BuildRestartStep();

		_root.Controls.Add(_updateStep);
		Controls.Add(_root);
	}

	private Panel BuildUpdateStep()
	{
		var panel = new FlowLayoutPanel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			FlowDirection = FlowDirection.TopDown,
			WrapContents = false,
		};

		panel.Controls.Add(Heading(string.Format(
			"Version {0} is available. Version {1} is installed.",
			Short(_info.AvailableVersion), Short(_info.InstalledVersion))));

		panel.Controls.Add(BuildDetails());

		panel.Controls.Add(Link("Update now", "KeePass restarts to load the new plugin", OnUpdateNow));

		var later = Link("Later", "Ask again at the next KeePass start",
			(s, e) => Finish(PluginUpdateChoice.Later));
		CancelButton = later;
		panel.Controls.Add(later);
		panel.Controls.Add(Link("Skip version " + Short(_info.AvailableVersion),
			"Ask again when a newer version arrives",
			(s, e) => Finish(PluginUpdateChoice.SkipThisVersion)));
		panel.Controls.Add(Link("Never check for plugin updates",
			"Can be re-enabled in the KeePassPasskey app's settings",
			(s, e) => Finish(PluginUpdateChoice.NeverCheck)));

		return panel;
	}

	private Panel BuildRestartStep()
	{
		var panel = new FlowLayoutPanel
		{
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			FlowDirection = FlowDirection.TopDown,
			WrapContents = false,
		};

		panel.Controls.Add(Heading("The plugin was updated to " + Short(_info.AvailableVersion) + "."));
		panel.Controls.Add(new Label
		{
			AutoSize = false,
			Margin = new Padding(3, 0, 3, 12),
			Size = new Size(ContentWidth, 20),
			Text = "KeePass has to restart before the new version is loaded.",
		});

		panel.Controls.Add(Link("Restart now", "KeePass closes and reopens", (s, e) =>
		{
			RestartRequested = true;
			Finish(PluginUpdateChoice.Update);
		}));
		_restartLater = Link("Later", "The new version loads at the next KeePass start",
			(s, e) => Finish(PluginUpdateChoice.Update));
		panel.Controls.Add(_restartLater);

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
		details.Controls.Add(new Label
		{
			AutoSize = true,
			Text = "KeePassPasskey (" + _info.ChannelDisplayName + ")",
		}, 1, 0);

		details.Controls.Add(new Label(), 0, 1);
		details.Controls.Add(PathLabel(_info.PackagePath, SystemColors.GrayText), 1, 1);

		details.Controls.Add(Caption("To"), 0, 2);
		details.Controls.Add(PathLabel(_info.TargetDirectory, SystemColors.ControlText), 1, 2);

		return details;
	}

	private Label Caption(string text) => new Label
	{
		AutoSize = true,
		ForeColor = SystemColors.GrayText,
		Margin = new Padding(3, 3, 14, 3),
		Text = text,
	};

	private Label PathLabel(string path, Color color)
	{
		var label = new Label
		{
			AutoEllipsis = true,
			AutoSize = false,
			ForeColor = color,
			Size = new Size(ContentWidth - 60, 18),
			Text = path ?? "",
		};
		_toolTip.SetToolTip(label, path ?? "");
		return label;
	}

	private static Label Heading(string text) => new Label
	{
		AutoSize = false,
		Font = new Font(SystemFonts.MessageBoxFont.FontFamily, SystemFonts.MessageBoxFont.Size + 1.5f),
		Margin = new Padding(3, 0, 3, 8),
		Size = new Size(ContentWidth, 24),
		Text = text,
	};

	private CommandLinkButton Link(string text, string note, EventHandler onClick)
	{
		var button = new CommandLinkButton
		{
			Note = note,
			Size = new Size(ContentWidth, LinkHeight),
			Text = text,
		};
		button.Click += onClick;
		return button;
	}

	private void OnUpdateNow(object sender, EventArgs e)
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
		{
			ShowRestartStep();
			return;
		}

		// A dismissed elevation prompt is a decision, not a failure, so it behaves like Later.
		if (!InstallOutcome.Cancelled)
		{
			KeePassLib.Utility.MessageService.ShowWarning(
				"The KeePassPasskey plugin could not be updated.",
				InstallOutcome.Error ?? "Unknown error.");
		}
		Finish(PluginUpdateChoice.Later);
	}

	private void ShowRestartStep()
	{
		Choice = PluginUpdateChoice.Update;
		// Pin the width so swapping to the shorter step only changes the height.
		MinimumSize = new Size(Width, 0);
		CancelButton = _restartLater;
		_root.Controls.Remove(_updateStep);
		_root.Controls.Add(_restartStep);
	}

	private void SetBusy(bool busy)
	{
		_updateStep.Enabled = !busy;
		Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
		Update();
	}

	private void Finish(PluginUpdateChoice choice)
	{
		Choice = choice;
		DialogResult = DialogResult.OK;
	}

	private static string Short(string version) => PipeConstants.StripBuildMetadata(version);

	protected override void Dispose(bool disposing)
	{
		if (disposing) _toolTip.Dispose();
		base.Dispose(disposing);
	}
}
