// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>Candidate entries of one database, as a collapsible group in the registration prompt.</summary>
public sealed partial class EntryGroupViewModel : ObservableObject
{
	private readonly Action<EntryGroupViewModel> _selectionChanged;

	[ObservableProperty] public partial bool IsExpanded { get; set; } = true;
	[ObservableProperty] public partial EntryRowViewModel? SelectedItem { get; set; }

	public string DatabaseName { get; }
	public ObservableCollection<EntryRowViewModel> Items { get; }
	public int Count => Items.Count;

	internal EntryGroupViewModel(
		string databaseName,
		IEnumerable<EntryRowViewModel> items,
		bool isExpanded,
		Action<EntryGroupViewModel> selectionChanged)
	{
		DatabaseName = databaseName;
		Items = new ObservableCollection<EntryRowViewModel>(items);
		IsExpanded = isExpanded;
		_selectionChanged = selectionChanged;
	}

	partial void OnSelectedItemChanged(EntryRowViewModel? value) => _selectionChanged(this);

	[RelayCommand]
	private void Toggle() => IsExpanded = !IsExpanded;
}
