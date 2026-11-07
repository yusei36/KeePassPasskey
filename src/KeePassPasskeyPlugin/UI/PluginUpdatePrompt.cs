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
using KeePassPasskeyShared.Localization;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.UI;

/// <summary>
/// The plugin update prompts, built on the same native task dialog KeePass uses for its own
/// questions. Each step is a dialog of its own rather than swapped content, so the install runs
/// between two of them and the elevation prompt never sits over a greyed-out window.
/// </summary>
internal static class PluginUpdatePrompt
{
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
		dialog.MainInstruction = Localizer.Format(Strings.KeePass_Update_Heading,
			Short(info.AvailableVersion), Short(info.InstalledVersion));
		dialog.Content = Strings.KeePass_Update_Message
			+ "\r\n\r\n" + Localizer.Format(Strings.KeePass_Update_FromLabel, info.ChannelDisplayName)
			+ "\r\n" + WrapPath(info.PackagePath)
			+ "\r\n\r\n" + WrapPath(Localizer.Format(Strings.KeePass_Update_ToLabel, info.TargetDirectory));
		dialog.AddButton(IdUpdate, Strings.KeePass_Update_UpdateNowButton, Strings.KeePass_Update_UpdateNowNote);
		dialog.AddButton(IdLater, Strings.KeePass_Update_LaterButton, Strings.KeePass_Update_LaterNote);
		dialog.AddButton(IdSkip, Localizer.Format(Strings.KeePass_Update_SkipVersionButton, Short(info.AvailableVersion)),
			Strings.KeePass_Update_SkipVersionNote);
		dialog.VerificationText = Strings.KeePass_Update_NeverCheckCheckbox;

		if (!dialog.ShowDialog(parent))
		{
			neverCheck = false;
			return MessageService.AskYesNo(Localizer.Format(Strings.KeePass_Update_FallbackQuestion, Short(info.AvailableVersion)))
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
		dialog.MainInstruction = Localizer.Format(Strings.KeePass_Restart_Heading, Short(info.AvailableVersion));
		dialog.Content = Strings.KeePass_Restart_Message;
		dialog.AddButton(IdRestart, Strings.KeePass_Restart_RestartNowButton, Strings.KeePass_Restart_RestartNowNote);
		dialog.AddButton(IdLater, Strings.KeePass_Update_LaterButton,
			Localizer.Format(Strings.KeePass_Restart_LaterNote, Short(info.InstalledVersion)));

		if (!dialog.ShowDialog(parent))
			return MessageService.AskYesNo(Strings.KeePass_Restart_FallbackQuestion);

		return dialog.Result == IdRestart;
	}

	/// <summary>True when the user wants the install run again.</summary>
	internal static bool ShowFailure(PluginInstallOutcome outcome, PluginUpdateInfo info, Form parent)
	{
		// A dismissed elevation prompt is a decision rather than an error, so it only reports what it
		// left behind. Anything else carries the reason the write failed.
		string reason = outcome.Cancelled
			? Localizer.Format(Strings.KeePass_UpdateFailed_PermissionDenied, Short(info.InstalledVersion))
			: outcome.Error ?? Strings.Common_Install_Error_WriteFailed;

		var dialog = NewDialog(VtdIcon.Warning);
		dialog.MainInstruction = Strings.KeePass_UpdateFailed_Heading;
		dialog.Content = reason;
		dialog.AddButton(IdRetry, Strings.KeePass_UpdateFailed_TryAgainButton,
			outcome.Cancelled ? Strings.KeePass_UpdateFailed_TryAgainPermissionNote : Strings.KeePass_UpdateFailed_TryAgainNote);
		dialog.AddButton(IdLater, Strings.KeePass_Update_LaterButton, Strings.KeePass_Update_LaterNote);

		if (!dialog.ShowDialog(parent))
			return MessageService.AskYesNo(Localizer.Format(Strings.KeePass_UpdateFailed_FallbackQuestion, reason));

		return dialog.Result == IdRetry;
	}

	private static VistaTaskDialog NewDialog(VtdIcon icon)
	{
		var dialog = new VistaTaskDialog { CommandLinks = true, WindowTitle = Strings.KeePass_Update_Title };
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
