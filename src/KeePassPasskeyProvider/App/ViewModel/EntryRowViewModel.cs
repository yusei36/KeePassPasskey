// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>One candidate entry a passkey can be saved onto, in the registration prompt's list.</summary>
public sealed class EntryRowViewModel
{
	public EntryMatchInfo Entry { get; }
	public string Title { get; }
	public string Subtitle { get; }
	public string Letter { get; }
	public IBrush TileBrush { get; }
	public IImage? Icon { get; }
	public bool HasIcon => Icon != null;
	public bool HasPasskey => Entry.HasPasskey;
	public bool IsKeePassSelected => Entry.IsSelected;

	/// <summary>The database name, which the group header already shows; kept for grouping and search.</summary>
	internal string DatabaseName { get; }

	internal EntryRowViewModel(EntryMatchInfo entry)
	{
		Entry = entry;
		Title = string.IsNullOrEmpty(entry.Title) ? "(untitled)" : entry.Title;
		DatabaseName = string.IsNullOrEmpty(entry.DatabaseName) ? "(unnamed database)" : entry.DatabaseName;
		Subtitle = entry.UserName ?? "";
		Letter = LetterTile.Letter(Title);
		TileBrush = LetterTile.Brush(Title);
		Icon = IconImage.FromBase64(entry.Icon);
	}

	internal bool Matches(string search)
		=> search.Length == 0
			|| Title.Contains(search, StringComparison.CurrentCultureIgnoreCase)
			|| Subtitle.Contains(search, StringComparison.CurrentCultureIgnoreCase)
			|| DatabaseName.Contains(search, StringComparison.CurrentCultureIgnoreCase);
}
