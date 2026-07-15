// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Utility;
using KeePassPasskey.Storage;

namespace KeePassPasskey.UI;

/// <summary>
/// Adds a "Passkey" submenu to the entry context menu: cut/copy/paste to move or copy a passkey
/// between entries (including across open databases; the source is held only in memory), and
/// remove to strip a passkey from an entry.
/// </summary>
internal sealed class EntryMenuController : IDisposable
{
	private readonly IPluginHost _host;
	private readonly PasskeyEntryStorage _storage;

	private ToolStripMenuItem _rootItem;
	private ToolStripMenuItem _cutItem;
	private ToolStripMenuItem _copyItem;
	private ToolStripMenuItem _pasteItem;
	private ToolStripMenuItem _removeItem;

	private PwDatabase _sourceDb;
	private PwEntry _sourceEntry;
	private bool _sourceIsCut;

	private bool _disposed;

	internal EntryMenuController(IPluginHost host, PasskeyEntryStorage storage)
	{
		_host = host;
		_storage = storage;
		_host.MainWindow.UIStateUpdated += OnUIStateUpdated;
	}

	internal ToolStripMenuItem GetEntryMenuItem()
	{
		if (_rootItem != null) return _rootItem;

		_cutItem = new ToolStripMenuItem("Cut Passkey", KeePassIcons.Get("B16x16_Cut"));
		_cutItem.Click += OnCut;

		_copyItem = new ToolStripMenuItem("Copy Passkey", KeePassIcons.Get("B16x16_EditCopy"));
		_copyItem.Click += OnCopy;

		_pasteItem = new ToolStripMenuItem("Paste Passkey Here", KeePassIcons.Get("B16x16_EditPaste"));
		_pasteItem.Click += OnPaste;

		_removeItem = new ToolStripMenuItem("Remove Passkey", KeePassIcons.Get("B16x16_DeleteEntry"));
		_removeItem.Click += OnRemove;

		_rootItem = new ToolStripMenuItem("Passkey", KeePassIcons.GetEntryIcon(_host, PwIcon.MultiKeys));
		_rootItem.DropDownItems.Add(_cutItem);
		_rootItem.DropDownItems.Add(_copyItem);
		_rootItem.DropDownItems.Add(_pasteItem);
		_rootItem.DropDownItems.Add(new ToolStripSeparator());
		_rootItem.DropDownItems.Add(_removeItem);

		UpdateMenuState();
		return _rootItem;
	}

	private void OnCut(object sender, EventArgs e) => SetSource(cut: true);

	private void OnCopy(object sender, EventArgs e) => SetSource(cut: false);

	private void SetSource(bool cut)
	{
		var entry = GetSingleSelectedEntry();
		if (entry == null || !PasskeyEntryStorage.EntryHasPasskey(entry)) return;

		_sourceDb = _host.Database;
		_sourceEntry = entry;
		_sourceIsCut = cut;
		UpdateMenuState();
	}

	private void OnPaste(object sender, EventArgs e)
	{
		if (_sourceEntry == null || _sourceDb == null) return;

		var target = GetSingleSelectedEntry();
		if (target == null || ReferenceEquals(target, _sourceEntry)) return;

		if (PasskeyEntryStorage.EntryHasPasskey(target) && !MessageService.AskYesNo(
			"This entry already contains a passkey. Replace it with the one you are pasting?\r\n\r\n" +
			"The current passkey remains in the entry's history, in case you need it back.",
			PwDefs.ShortProductName))
			return;

		var result = _storage.TransferPasskey(_sourceDb, _sourceEntry, _host.Database, target, _sourceIsCut);
		switch (result)
		{
			case PasskeyTransferResult.Success:
				if (_sourceIsCut) ClearSource(); // a copy stays on the clipboard for further pastes
				break;
			case PasskeyTransferResult.SameEntry:
				MessageService.ShowInfo("The passkey is already on this entry.");
				break;
			case PasskeyTransferResult.SourceUnavailable:
				MessageService.ShowWarning(
					"The entry the passkey came from is no longer available, so the paste was cancelled.");
				ClearSource();
				break;
			default:
				MessageService.ShowWarning("The passkey could not be pasted.");
				break;
		}

		UpdateMenuState();
	}

	private void OnRemove(object sender, EventArgs e)
	{
		var entry = GetSingleSelectedEntry();
		if (entry == null || !PasskeyEntryStorage.EntryHasPasskey(entry)) return;

		var title = _storage.ResolveEntryTitle(entry, _host.Database);
		if (!MessageService.AskYesNo(
			(string.IsNullOrEmpty(title)
				? "Remove the passkey from this entry?"
				: "Remove the passkey from “" + title + "”?") + "\r\n\r\n" +
			"The entry itself is kept. The passkey remains in the entry's history, in case " +
			"you need it back.",
			PwDefs.ShortProductName, false))
			return;

		if (!_storage.RemovePasskey(_host.Database, entry))
		{
			MessageService.ShowWarning("The passkey could not be removed.");
			return;
		}

		if (ReferenceEquals(entry, _sourceEntry)) ClearSource();
		UpdateMenuState();
	}

	private void OnUIStateUpdated(object sender, EventArgs e) => UpdateMenuState();

	private void UpdateMenuState()
	{
		if (_rootItem == null) return;

		// Drop a stale source when its database was closed.
		if (_sourceDb != null && !_sourceDb.IsOpen)
			ClearSource();

		var entry = GetSingleSelectedEntry();
		bool hasSource = _sourceEntry != null && _sourceDb != null && _sourceDb.IsOpen;

		_cutItem.Enabled = true;
		_copyItem.Enabled = true;
		_pasteItem.Enabled = hasSource && entry != null && !ReferenceEquals(entry, _sourceEntry);
		_removeItem.Enabled = entry != null && PasskeyEntryStorage.EntryHasPasskey(entry);

		if (hasSource)
		{
			var title = _storage.ResolveEntryTitle(_sourceEntry, _sourceDb);
			_pasteItem.Text = string.IsNullOrEmpty(title)
				? "Paste Passkey Here"
				: "Paste Passkey from “" + title + "”";
		}
		else
		{
			_pasteItem.Text = "Paste Passkey Here";
		}
	}

	private void ClearSource()
	{
		_sourceDb = null;
		_sourceEntry = null;
	}

	private PwEntry GetSingleSelectedEntry()
	{
		var entries = _host.MainWindow.GetSelectedEntries();
		return (entries != null && entries.Length == 1) ? entries[0] : null;
	}

	public void Dispose()
	{
		if (_disposed) return;
		_disposed = true;

		_host.MainWindow.UIStateUpdated -= OnUIStateUpdated;

		if (_cutItem != null) _cutItem.Click -= OnCut;
		if (_copyItem != null) _copyItem.Click -= OnCopy;
		if (_pasteItem != null) _pasteItem.Click -= OnPaste;
		if (_removeItem != null) _removeItem.Click -= OnRemove;
		_rootItem?.Dispose();

		ClearSource();
	}
}
