// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using KeePass.UI;
using KeePassLib.Utility;
using KeePassPasskey.Update;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.UI;

/// <summary>
/// The plugin update prompts, built on the same native task dialog KeePass uses for its own
/// questions. Each step is a dialog of its own rather than swapped content, so the install runs
/// between two of them and the elevation prompt never sits over a greyed-out window.
/// </summary>
internal static class PluginUpdatePrompt
{
	private const string Title = "KeePassPasskey plugin update";

	// Ids stay clear of the standard IDOK/IDCANCEL/IDYES/IDNO, so closing with Esc or the title bar
	// (which reports IDCANCEL) cannot be mistaken for one of ours.
	private const int IdUpdate = 101;
	private const int IdLater = 102;
	private const int IdSkip = 103;
	private const int IdRestart = 104;
	private const int IdRetry = 105;

	// The dialog word-wraps a path and then ellipsises whatever still does not fit, which eats the
	// middle of a WindowsApps path. Breaking it ourselves keeps every character readable.
	private const int PathLineLength = 60;

	internal static PluginUpdateChoice ShowUpdate(PluginUpdateInfo info, Form parent, out bool neverCheck)
	{
		var dialog = NewDialog(VtdIcon.Information);
		dialog.MainInstruction = string.Format("Version {0} is available. Version {1} is installed.",
			Short(info.AvailableVersion), Short(info.InstalledVersion));
		dialog.Content = "Creating and using passkeys can stop working until these match."
			+ "\r\n\r\nFrom:  KeePassPasskey (" + info.ChannelDisplayName + ")"
			+ "\r\n" + WrapPath(info.PackagePath)
			+ "\r\n\r\n" + WrapPath("To:  " + info.TargetDirectory);
		dialog.AddButton(IdUpdate, "Update now", "KeePass has to restart afterwards to load it");
		dialog.AddButton(IdLater, "Later", "Ask again at the next KeePass start");
		dialog.AddButton(IdSkip, "Skip version " + Short(info.AvailableVersion),
			"Do not ask again for this version");
		dialog.VerificationText = "Don't check for plugin updates again";

		if (!dialog.ShowDialog(parent))
		{
			neverCheck = false;
			return MessageService.AskYesNo("A new KeePassPasskey plugin is available (version "
				+ Short(info.AvailableVersion) + "). Install it now?")
				? PluginUpdateChoice.Update
				: PluginUpdateChoice.Later;
		}

		neverCheck = dialog.ResultVerificationChecked;
		switch (dialog.Result)
		{
			case IdUpdate: return PluginUpdateChoice.Update;
			case IdSkip: return PluginUpdateChoice.SkipThisVersion;
			default: return PluginUpdateChoice.Later;
		}
	}

	/// <summary>True when KeePass should restart now.</summary>
	internal static bool ShowRestart(PluginUpdateInfo info, Form parent)
	{
		var dialog = NewDialog(VtdIcon.Information);
		dialog.MainInstruction = "The plugin was updated to " + Short(info.AvailableVersion) + ".";
		dialog.Content = "KeePass has to restart before the new version is loaded.";
		dialog.AddButton(IdRestart, "Restart now", "KeePass closes and reopens");
		dialog.AddButton(IdLater, "Later",
			Short(info.InstalledVersion) + " stays in use until KeePass restarts");

		if (!dialog.ShowDialog(parent))
			return MessageService.AskYesNo("The KeePassPasskey plugin was updated. Restart KeePass now?");

		return dialog.Result == IdRestart;
	}

	/// <summary>True when the user wants the install run again.</summary>
	internal static bool ShowFailure(PluginInstallOutcome outcome, PluginUpdateInfo info, Form parent)
	{
		// A dismissed elevation prompt is a decision rather than an error, so it only reports what it
		// left behind. Anything else carries the reason the write failed.
		string reason = outcome.Cancelled
			? "Permission was not granted, so version " + Short(info.InstalledVersion) + " is still in use."
			: outcome.Error ?? "The plugin file could not be written.";

		var dialog = NewDialog(VtdIcon.Warning);
		dialog.MainInstruction = "The plugin was not updated.";
		dialog.Content = reason;
		dialog.AddButton(IdRetry, "Try again",
			outcome.Cancelled ? "Asks for permission once more" : "Runs the update again");
		dialog.AddButton(IdLater, "Later", "Ask again at the next KeePass start");

		if (!dialog.ShowDialog(parent))
			return MessageService.AskYesNo(reason + "\r\n\r\nTry again?");

		return dialog.Result == IdRetry;
	}

	private static VistaTaskDialog NewDialog(VtdIcon icon)
	{
		var dialog = new VistaTaskDialog { CommandLinks = true, WindowTitle = Title };
		dialog.SetIcon(icon);
		AllowCancellation(dialog);
		return dialog;
	}

	/// <summary>
	/// Turns on the close button and Esc. KeePass's wrapper leaves the flag off and does not expose
	/// it, and a prompt that appears on its own at startup has to be dismissable. Should the field
	/// ever be renamed, the only loss is the close button.
	/// </summary>
	private static void AllowCancellation(VistaTaskDialog dialog)
	{
		try
		{
			var configField = typeof(VistaTaskDialog).GetField("m_cfg",
				BindingFlags.NonPublic | BindingFlags.Instance);
			// The config is a struct, so this is a copy that has to be written back.
			object config = configField?.GetValue(dialog);
			var flagsField = config?.GetType().GetField("dwFlags",
				BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
			if (flagsField == null)
				return;

			var flags = (VtdFlags)flagsField.GetValue(config);
			flagsField.SetValue(config, flags | VtdFlags.AllowDialogCancellation);
			configField.SetValue(dialog, config);
		}
		catch
		{
			// Cosmetic only; the buttons still answer the prompt.
		}
	}

	/// <summary>
	/// Breaks a path at its separators so no line reaches the width at which the dialog would wrap it
	/// mid-segment. A segment too long for a whole line of its own is split where it runs out.
	/// </summary>
	private static string WrapPath(string path)
	{
		if (string.IsNullOrEmpty(path))
			return "";

		var lines = new List<string>();
		var line = new StringBuilder();

		foreach (string segment in SplitAfterSeparators(path))
		{
			string rest = segment;
			while (rest.Length > PathLineLength)
			{
				if (line.Length > 0)
				{
					lines.Add(line.ToString());
					line.Length = 0;
				}
				lines.Add(rest.Substring(0, PathLineLength));
				rest = rest.Substring(PathLineLength);
			}

			if (line.Length + rest.Length > PathLineLength)
			{
				lines.Add(line.ToString());
				line.Length = 0;
			}
			line.Append(rest);
		}

		if (line.Length > 0)
			lines.Add(line.ToString());

		return string.Join("\r\n", lines.ToArray());
	}

	private static IEnumerable<string> SplitAfterSeparators(string path)
	{
		int start = 0;
		for (int i = 0; i < path.Length; i++)
		{
			if (path[i] != '\\')
				continue;
			yield return path.Substring(start, i - start + 1);
			start = i + 1;
		}
		if (start < path.Length)
			yield return path.Substring(start);
	}

	private static string Short(string version) => PipeConstants.StripBuildMetadata(version);
}
