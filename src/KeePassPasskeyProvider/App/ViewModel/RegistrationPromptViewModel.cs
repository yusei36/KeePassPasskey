// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>
/// Registration prompt: confirm the ceremony and pick where the passkey goes, a new entry in a
/// chosen database or an existing entry from the searchable candidate list.
/// </summary>
public sealed partial class RegistrationPromptViewModel : PromptViewModelBase
{
	private readonly List<EntryRowViewModel> _allRows;
	private readonly Dictionary<string, bool> _expanded = new(StringComparer.Ordinal);
	private bool _syncingSelection;

	// Two properties rather than one negated binding, so the initial state does not depend on the
	// order the segmented control's bindings initialise in.
	[ObservableProperty] public partial bool IsCreateNew { get; set; } = true;
	[ObservableProperty] public partial bool IsAddToExisting { get; set; }
	[ObservableProperty] public partial DatabaseInfo? SelectedDatabase { get; set; }
	[ObservableProperty] public partial string SearchText { get; set; } = "";
	[ObservableProperty] public partial bool OnlyWithPasskey { get; set; }
	[ObservableProperty] public partial EntryRowViewModel? SelectedEntry { get; set; }
	[ObservableProperty] public partial bool HasVisibleEntries { get; set; } = true;

	public IReadOnlyList<DatabaseInfo> Databases { get; }
	public ObservableCollection<EntryGroupViewModel> Groups { get; } = [];
	public bool HasCandidates { get; }

	public override bool CanConfirm => IsAddToExisting ? SelectedEntry != null : SelectedDatabase != null;

	internal RegistrationPromptViewModel(
		string rpId,
		string rpName,
		string userName,
		IReadOnlyList<DatabaseInfo> databases,
		IReadOnlyList<EntryMatchInfo> candidates)
	{
		string site = rpName.Length > 0 ? rpName : rpId;
		WindowTitle = "Save passkey";
		ConfirmText = "Save";
		SetSite($"{site} wants to save a passkey", userName.Length > 0 ? $"as {userName}" : "", site);

		Databases = databases;
		SelectedDatabase = databases.Count > 0 ? databases[0] : null;

		_allRows = [.. candidates.Select(c => new EntryRowViewModel(c))];
		HasCandidates = _allRows.Count > 0;

		RebuildGroups();

		// Candidates arrive ranked best first (entry selected in KeePass, then RP-id, then URL host).
		if (Groups.Count > 0 && Groups[0].Items.Count > 0)
			Groups[0].SelectedItem = Groups[0].Items[0];
	}

	/// <summary>The entry the passkey should be written onto, or null when a new entry is wanted.</summary>
	internal EntryTargetInfo? TargetEntry => IsAddToExisting && SelectedEntry != null
		? new EntryTargetInfo { EntryUuid = SelectedEntry.Entry.EntryUuid, DatabaseId = SelectedEntry.Entry.DatabaseId }
		: null;

	/// <summary>The database a new entry should be created in, or null when saving onto an existing entry.</summary>
	internal DatabaseInfo? TargetDatabase => IsAddToExisting ? null : SelectedDatabase;

	partial void OnIsCreateNewChanged(bool value)
	{
		if (IsAddToExisting == !value) return;
		IsAddToExisting = !value;
	}

	partial void OnIsAddToExistingChanged(bool value)
	{
		if (IsCreateNew != !value) IsCreateNew = !value;
		OnPropertyChanged(nameof(CanConfirm));
	}

	partial void OnSelectedDatabaseChanged(DatabaseInfo? value) => OnPropertyChanged(nameof(CanConfirm));
	partial void OnSelectedEntryChanged(EntryRowViewModel? value) => OnPropertyChanged(nameof(CanConfirm));
	partial void OnSearchTextChanged(string value) => RebuildGroups();
	partial void OnOnlyWithPasskeyChanged(bool value) => RebuildGroups();

	// One ListBox per database group, so selecting in one has to clear the others.
	private void OnGroupSelectionChanged(EntryGroupViewModel group)
	{
		if (_syncingSelection) return;

		_syncingSelection = true;
		try
		{
			if (group.SelectedItem == null)
			{
				if (SelectedEntry != null && group.Items.Contains(SelectedEntry))
					SelectedEntry = null;
				return;
			}

			foreach (var other in Groups)
			{
				if (!ReferenceEquals(other, group))
					other.SelectedItem = null;
			}
			SelectedEntry = group.SelectedItem;
		}
		finally
		{
			_syncingSelection = false;
		}
	}

	private void RebuildGroups()
	{
		foreach (var group in Groups)
			_expanded[group.DatabaseName] = group.IsExpanded;

		var previous = SelectedEntry;

		_syncingSelection = true;
		Groups.Clear();
		_syncingSelection = false;

		string search = SearchText.Trim();
		var visible = _allRows.Where(r => (!OnlyWithPasskey || r.HasPasskey) && r.Matches(search)).ToList();

		// Enumeration order is the plugin's ranking, so groups and rows both stay ranked.
		foreach (var group in visible.GroupBy(r => r.Subtitle, StringComparer.Ordinal))
			Groups.Add(new EntryGroupViewModel(group.Key, group, _expanded.GetValueOrDefault(group.Key, true), OnGroupSelectionChanged));

		HasVisibleEntries = visible.Count > 0;

		if (previous != null && visible.Contains(previous))
		{
			var owner = Groups.FirstOrDefault(g => g.Items.Contains(previous));
			if (owner != null) owner.SelectedItem = previous;
		}
		else
		{
			SelectedEntry = null;
		}
	}
}
