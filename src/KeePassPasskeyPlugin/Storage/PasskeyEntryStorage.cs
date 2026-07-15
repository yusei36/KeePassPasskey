// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;
using KeePassPasskey.Passkey;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskey.Storage;

internal sealed class PasskeyEntryStorage
{
	private static readonly Guid PasskeyGroupUuid = new Guid("c3eeec14-998f-458c-924d-79bb98732a18");
	private const string PasskeyGroupName = "Passkeys";
	private const string PasskeyTagName = "Passkey";
	private const string RpNameToken = "{RP_NAME}";
	private const string KeePassXcPasskeyGroupName = "KeePassXC-Browser Passkeys";
	private const string FieldCredentialId = "KPEX_PASSKEY_CREDENTIAL_ID";
	private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
	private const string FieldRelyingParty = "KPEX_PASSKEY_RELYING_PARTY";
	private const string FieldUserHandle = "KPEX_PASSKEY_USER_HANDLE";
	private const string FieldUsername = "KPEX_PASSKEY_USERNAME";
	private const string FieldFlagBe = "KPEX_PASSKEY_FLAG_BE";
	private const string FieldFlagBs = "KPEX_PASSKEY_FLAG_BS";

	private readonly IPluginHost _host;
	private readonly SettingsStorage _settingsStorage;

	internal PasskeyEntryStorage(IPluginHost host, SettingsStorage settingsStorage)
	{
		_host = host;
		_settingsStorage = settingsStorage;
	}

	internal bool CreatePasskeyEntry(PasskeyCredential credential, DatabaseInfo target = null)
	{
		var settings = _settingsStorage.Load();

		var entry = new PwEntry(true, true);
		entry.IconId = PwIcon.MultiKeys;
		entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, credential.Username ?? ""));
		entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, credential.Origin ?? ""));
		entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, ""));

		ApplyPasskeyFields(entry, credential);

		if (settings.AddPasskeyTag)
			entry.AddTag(PasskeyTagName);

		var db = ResolveDatabaseOrFallback(target, nameof(CreatePasskeyEntry));
		if (db == null || !db.IsOpen) return false;

		// Title is built last so its placeholders can resolve against the populated entry.
		entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, BuildTitle(settings, credential, entry, db)));

		var targetGroup = ResolveTargetGroup(db, settings);
		targetGroup.AddEntry(entry, true);

		RefreshAndSave(db);
		return true;
	}

	// Writes the passkey onto an existing entry (e.g. the site's login entry) instead of
	// creating a new one. The entry's prior state is pushed onto KeePass's history first so
	// the user can restore it; Title/URL/UserName the user already set are preserved.
	internal bool AddPasskeyToExistingEntry(PasskeyCredential credential, EntryTargetInfo target)
	{
		if (target == null || string.IsNullOrEmpty(target.EntryUuid))
			return false;

		var settings = _settingsStorage.Load();

		var uuid = new PwUuid(MemUtil.HexStringToByteArray(target.EntryUuid));
		PwDatabase db = null;
		PwEntry entry = null;
		foreach (var candidate in GetSearchDatabases())
		{
			if (!string.IsNullOrEmpty(target.DatabaseId)
				&& !string.Equals(candidate.RootGroup.Uuid.ToHexString(), target.DatabaseId, StringComparison.Ordinal))
				continue;
			var found = candidate.RootGroup.FindEntry(uuid, true);
			if (found != null) { db = candidate; entry = found; break; }
		}

		// Fall back to a database-agnostic search if the id did not match (e.g. the entry moved).
		if (entry == null)
		{
			foreach (var candidate in GetSearchDatabases())
			{
				var found = candidate.RootGroup.FindEntry(uuid, true);
				if (found != null) { db = candidate; entry = found; break; }
			}
		}

		if (entry == null || db == null || !db.IsOpen)
		{
			Log.Warn($"Target entry {target.EntryUuid} not found for passkey save", nameof(AddPasskeyToExistingEntry));
			return false;
		}

		entry.CreateBackup(db); // preserve the pre-overwrite state in the entry's history

		ApplyPasskeyFields(entry, credential);

		if (settings.AddPasskeyTag)
			entry.AddTag(PasskeyTagName);

		// Only fill URL/UserName when empty so the user's existing login data is preserved.
		if (string.IsNullOrEmpty(entry.Strings.ReadSafe(PwDefs.UrlField)) && !string.IsNullOrEmpty(credential.Origin))
			entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, credential.Origin));
		if (string.IsNullOrEmpty(entry.Strings.ReadSafe(PwDefs.UserNameField)) && !string.IsNullOrEmpty(credential.Username))
			entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, credential.Username));

		entry.Touch(true);

		RefreshAndSave(db);
		return true;
	}

	// Copies a passkey onto another entry (across databases when needed), backing up the target's
	// history first. When removeFromSource is set it becomes a move: the source is backed up and
	// its passkey stripped. The source keeps the passkey until the paste succeeds.
	internal PasskeyTransferResult TransferPasskey(PwDatabase sourceDb, PwEntry sourceEntry, PwDatabase targetDb, PwEntry targetEntry, bool removeFromSource)
	{
		if (sourceDb == null || sourceEntry == null || targetDb == null || targetEntry == null)
			return PasskeyTransferResult.Failed;
		if (ReferenceEquals(sourceEntry, targetEntry))
			return PasskeyTransferResult.SameEntry;

		// Source must still be live (not deleted or its database closed since the cut/copy).
		if (!sourceDb.IsOpen || sourceDb.RootGroup.FindEntry(sourceEntry.Uuid, true) == null || !EntryHasPasskey(sourceEntry))
			return PasskeyTransferResult.SourceUnavailable;
		if (!targetDb.IsOpen)
			return PasskeyTransferResult.Failed;

		var settings = _settingsStorage.Load();
		var credential = ExtractCredential(sourceEntry, sourceDb);
		var sourceUrl = sourceEntry.Strings.ReadSafe(PwDefs.UrlField);

		// Target: back up history, write the passkey, fill URL/UserName only when empty.
		targetEntry.CreateBackup(targetDb);
		ApplyPasskeyFields(targetEntry, credential);
		if (settings.AddPasskeyTag)
			targetEntry.AddTag(PasskeyTagName);
		if (string.IsNullOrEmpty(targetEntry.Strings.ReadSafe(PwDefs.UrlField)) && !string.IsNullOrEmpty(sourceUrl))
			targetEntry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, sourceUrl));
		if (string.IsNullOrEmpty(targetEntry.Strings.ReadSafe(PwDefs.UserNameField)) && !string.IsNullOrEmpty(credential.Username))
			targetEntry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, credential.Username));
		targetEntry.Touch(true);

		if (removeFromSource)
		{
			// Source: back up history, then strip the passkey so this is a move, not a copy.
			sourceEntry.CreateBackup(sourceDb);
			RemovePasskeyFields(sourceEntry);
			sourceEntry.RemoveTag(PasskeyTagName);
			sourceEntry.Touch(true);
			RefreshAndSave(targetDb, sourceDb);
		}
		else
		{
			RefreshAndSave(targetDb);
		}

		return PasskeyTransferResult.Success;
	}

	// Strips the passkey from an entry. The prior state is pushed onto the entry's history first,
	// so the passkey can still be restored from there.
	internal bool RemovePasskey(PwDatabase db, PwEntry entry)
	{
		if (db == null || !db.IsOpen || entry == null) return false;
		if (db.RootGroup.FindEntry(entry.Uuid, true) == null || !EntryHasPasskey(entry)) return false;

		entry.CreateBackup(db);
		RemovePasskeyFields(entry);
		entry.RemoveTag(PasskeyTagName);
		entry.Touch(true);

		RefreshAndSave(db);
		return true;
	}

	// Resolves an entry's title placeholders for display (e.g. the paste menu label).
	internal string ResolveEntryTitle(PwEntry entry, PwDatabase db)
	{
		if (entry == null || db == null) return string.Empty;
		return ResolveTitle(entry, db);
	}

	internal static bool EntryHasPasskey(PwEntry entry)
	{
		return entry != null
			&& entry.Strings.Exists(FieldCredentialId)
			&& !string.IsNullOrEmpty(entry.Strings.ReadSafe(FieldCredentialId));
	}

	private static void RemovePasskeyFields(PwEntry entry)
	{
		entry.Strings.Remove(FieldCredentialId);
		entry.Strings.Remove(FieldPrivateKey);
		entry.Strings.Remove(FieldRelyingParty);
		entry.Strings.Remove(FieldUserHandle);
		entry.Strings.Remove(FieldUsername);
		entry.Strings.Remove(FieldFlagBe);
		entry.Strings.Remove(FieldFlagBs);
	}

	// Sets the KPEX_PASSKEY_* fields (and BE/BS flags) on an entry. Shared by new-entry
	// creation and save-to-existing-entry so both write identical passkey material.
	private static void ApplyPasskeyFields(PwEntry entry, PasskeyCredential credential)
	{
		entry.Strings.Set(FieldCredentialId, new ProtectedString(true, credential.CredentialId));
		entry.Strings.Set(FieldPrivateKey, new ProtectedString(true, credential.PrivateKeyPem));
		entry.Strings.Set(FieldRelyingParty, new ProtectedString(false, credential.RelyingParty));
		entry.Strings.Set(FieldUserHandle, new ProtectedString(true, credential.UserHandle ?? ""));
		entry.Strings.Set(FieldUsername, new ProtectedString(false, credential.Username ?? ""));

		bool be = credential.BackupEligible;
		bool bs = credential.BackupState && be; // BS implies BE.
		entry.Strings.Set(FieldFlagBe, new ProtectedString(false, be ? "1" : "0"));
		entry.Strings.Set(FieldFlagBs, new ProtectedString(false, bs ? "1" : "0"));
	}

	// Refreshes the UI and (when auto-save is on) saves each affected database.
	private void RefreshAndSave(params PwDatabase[] databases)
	{
		var affected = databases.Where(d => d != null && d.IsOpen).Distinct().ToArray();
		if (affected.Length == 0) return;

		_host.MainWindow.BeginInvoke(new MethodInvoker(() =>
		{
			_host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
			if (KeePass.Program.Config.Application.AutoSaveAfterEntryEdit)
			{
				foreach (var db in affected)
					_host.MainWindow.SaveDatabase(db, null);
			}
		}));
	}

	// Builds the title from the template. Placeholders are compiled first (when enabled), then the
	// untrusted {RP_NAME} is spliced in last with its braces stripped so it can never act as one.
	private static string BuildTitle(KeePassPasskeySettings settings, PasskeyCredential credential, PwEntry entry, PwDatabase db)
	{
		var template = settings.EntryTitleTemplate;
		if (string.IsNullOrEmpty(template))
			template = "{RP_NAME} (Passkey)";

		if (settings.ResolveTitlePlaceholders)
			template = CompileTitle(template, entry, db);

		var rpName = !string.IsNullOrEmpty(credential.RpName) ? credential.RpName : credential.RelyingParty;
		return ReplaceIgnoreCase(template, RpNameToken, NeutralizePlaceholders(rpName ?? ""));
	}

	// Compiles a title's placeholders against a sanitized clone, so field values resolve as inert
	// text and cannot inject further placeholders (e.g. a username of "{S:..PRIVATE_KEY..}").
	// Titles without placeholders skip the clone, keeping metadata listing cheap.
	private static string CompileTitle(string text, PwEntry entry, PwDatabase db)
	{
		if (string.IsNullOrEmpty(text) || text.IndexOf('{') < 0) return text;
		return SprEngine.Compile(text, new SprContext(CloneWithoutProtectedFields(entry), db, SprCompileFlags.Deref));
	}

	// Removes placeholder braces so the text cannot be parsed as a KeePass placeholder.
	private static string NeutralizePlaceholders(string value) =>
		value.Replace("{", "").Replace("}", "");

	// Lightweight copy used only for title compilation: just the string fields SprEngine reads
	// under Deref ({USERNAME}, {URL}, {S:...}; {REF:...} resolves via the database). Protected
	// fields are blanked (never decrypted or shown) and the rest are brace-stripped so they
	// resolve as inert text.
	private static PwEntry CloneWithoutProtectedFields(PwEntry entry)
	{
		var copy = new PwEntry(false, false);
		foreach (var kvp in entry.Strings)
			copy.Strings.Set(kvp.Key, kvp.Value.IsProtected
				? new ProtectedString(true, "")
				: new ProtectedString(false, NeutralizePlaceholders(kvp.Value.ReadString())));
		return copy;
	}

	private static string ReplaceIgnoreCase(string input, string token, string value)
	{
		int idx = input.IndexOf(token, StringComparison.OrdinalIgnoreCase);
		if (idx < 0) return input;

		var sb = new System.Text.StringBuilder();
		int start = 0;
		while (idx >= 0)
		{
			sb.Append(input, start, idx - start);
			sb.Append(value);
			start = idx + token.Length;
			idx = input.IndexOf(token, start, StringComparison.OrdinalIgnoreCase);
		}
		sb.Append(input, start, input.Length - start);
		return sb.ToString();
	}

	internal List<PasskeyCredential> FindByRpId(string rpId)
	{
		var results = new List<PasskeyCredential>();
		foreach (var db in GetSearchDatabases())
		{
			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;
				if (!entry.Strings.Exists(FieldRelyingParty)) continue;
				var entryRpId = entry.Strings.ReadSafe(FieldRelyingParty);
				if (string.Equals(entryRpId, rpId, StringComparison.OrdinalIgnoreCase))
					results.Add(ExtractCredential(entry, db));
			}
		}
		return results;
	}

	internal PasskeyCredential FindByRpIdAndCredentialId(string rpId, string credentialId)
	{
		return FindByRpIdAndCredentialIds(rpId, new List<string> { credentialId }).FirstOrDefault();
	}

	internal List<PasskeyCredential> FindByRpIdAndCredentialIds(string rpId, List<string> credentialIds)
	{
		var results = new List<PasskeyCredential>();
		var credIdSet = new HashSet<string>(credentialIds, StringComparer.Ordinal);

		foreach (var db in GetSearchDatabases())
		{
			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;
				if (!entry.Strings.Exists(FieldRelyingParty)) continue;
				var entryRpId = entry.Strings.ReadSafe(FieldRelyingParty);
				if (!string.Equals(entryRpId, rpId, StringComparison.OrdinalIgnoreCase)) continue;
				var entryCredId = entry.Strings.ReadSafe(FieldCredentialId);
				if (credIdSet.Contains(entryCredId))
					results.Add(ExtractCredential(entry, db));
			}
		}
		return results;
	}

	// Finds existing entries a passkey could be attached to: entries already tagged with this
	// RP id, or ordinary login entries whose URL host matches the RP id (host == rpId or a
	// subdomain). Each result carries whether it already holds a passkey so the UI can label it.
	// Results are ranked so the most relevant survive the picker's item cap: the entry the user
	// has selected in KeePass first, then RP-id matches, then URL-host-only matches; enumeration
	// order is preserved within each group.
	internal List<EntryMatchInfo> FindMatchingEntries(string rpId)
	{
		if (string.IsNullOrEmpty(rpId)) return new List<EntryMatchInfo>();

		var selectedUuids = GetSelectedEntryUuids();
		var ranked = new List<(int rank, EntryMatchInfo info)>();

		foreach (var db in GetSearchDatabases())
		{
			string dbId = db.RootGroup.Uuid.ToHexString();
			string dbName = string.IsNullOrEmpty(db.Name) ? "(unnamed)" : db.Name;

			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;

				bool hasPasskey = entry.Strings.Exists(FieldCredentialId)
					&& !string.IsNullOrEmpty(entry.Strings.ReadSafe(FieldCredentialId));

				bool rpMatch = entry.Strings.Exists(FieldRelyingParty)
					&& string.Equals(entry.Strings.ReadSafe(FieldRelyingParty), rpId, StringComparison.OrdinalIgnoreCase);

				bool urlMatch = RpIdMatcher.UrlHostMatchesRpId(entry.Strings.ReadSafe(PwDefs.UrlField), rpId);

				if (!rpMatch && !urlMatch) continue;

				string uuidHex = entry.Uuid.ToHexString();
				bool isSelected = selectedUuids.Contains(uuidHex);

				var info = new EntryMatchInfo
				{
					EntryUuid = uuidHex,
					DatabaseId = dbId,
					DatabaseName = dbName,
					Title = ResolveTitle(entry, db),
					HasPasskey = hasPasskey,
					IsSelected = isSelected,
				};

				int rank = isSelected ? 0 : (rpMatch ? 1 : 2);
				ranked.Add((rank, info));
			}
		}

		return ranked.OrderBy(r => r.rank).Select(r => r.info).ToList();
	}

	private HashSet<string> GetSelectedEntryUuids()
	{
		var set = new HashSet<string>(StringComparer.Ordinal);
		try
		{
			var mw = _host.MainWindow;
			PwEntry[] selected = null;
			if (mw.InvokeRequired)
				mw.Invoke(new MethodInvoker(() => selected = mw.GetSelectedEntries()));
			else
				selected = mw.GetSelectedEntries();

			if (selected != null)
				foreach (var e in selected)
					set.Add(e.Uuid.ToHexString());
		}
		catch (Exception ex)
		{
			Log.Warn("failed to read selected entries: " + ex.Message, nameof(GetSelectedEntryUuids));
		}
		return set;
	}

	// Does an excluded credential already exist for this RP within the ExcludeCredentialCheckMode scope?
	internal bool HasExcludeCredential(string rpId, List<string> credentialIds, DatabaseInfo targetDatabase, EntryTargetInfo targetEntry)
	{
		if (credentialIds == null || credentialIds.Count == 0) return false;

		var mode = _settingsStorage.Load().ExcludeCredentialCheckMode;
		if (mode == ExcludeCredentialCheckMode.None) return false;

		var databases = mode == ExcludeCredentialCheckMode.AllDatabases
			? GetSearchDatabases()
			: new List<PwDatabase> { ResolveTargetDatabase(targetDatabase, targetEntry) };

		var credIdSet = new HashSet<string>(credentialIds, StringComparer.Ordinal);

		foreach (var db in databases)
		{
			if (db == null || !db.IsOpen) continue;
			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;
				if (!entry.Strings.Exists(FieldCredentialId)) continue;
				if (!credIdSet.Contains(entry.Strings.ReadSafe(FieldCredentialId))) continue;
				if (!entry.Strings.Exists(FieldRelyingParty)) continue;
				if (string.Equals(entry.Strings.ReadSafe(FieldRelyingParty), rpId, StringComparison.OrdinalIgnoreCase))
					return true;
			}
		}
		return false;
	}

	internal bool HasCredentialForRpId(string rpId, string credentialIdBase64Url)
	{
		foreach (var db in GetSearchDatabases())
		{
			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;
				if (!entry.Strings.Exists(FieldCredentialId)) continue;
				var entryCredId = entry.Strings.ReadSafe(FieldCredentialId);
				if (!string.Equals(entryCredId, credentialIdBase64Url, StringComparison.Ordinal)) continue;
				if (!entry.Strings.Exists(FieldRelyingParty)) continue;
				var entryRpId = entry.Strings.ReadSafe(FieldRelyingParty);
				if (string.Equals(entryRpId, rpId, StringComparison.OrdinalIgnoreCase))
					return true;
			}
		}
		return false;
	}

	internal List<PasskeyCredential> GetAllCredentials()
	{
		var results = new List<PasskeyCredential>();
		foreach (var db in GetSearchDatabases())
		{
			foreach (var entry in db.RootGroup.GetEntries(true))
			{
				if (!IsSearchable(entry)) continue;
				if (entry.Strings.Exists(FieldCredentialId) && entry.Strings.Exists(FieldRelyingParty))
					results.Add(ExtractCredentialMetadata(entry, db));
			}
		}
		return results;
	}

	// Order-independent signature of the passkey set across open databases, over the fields that
	// reach the Windows cache. The plugin compares it to detect real passkey changes before
	// syncing; reordering doesn't change it (per-entry hashes are XORed). Uses the raw
	// (uncompiled) title to stay cheap.
	internal string ComputePasskeySignature()
	{
		var acc = new byte[32];
		int count = 0;
		using (var sha = SHA256.Create())
		{
			foreach (var db in GetSearchDatabases())
			{
				foreach (var entry in db.RootGroup.GetEntries(true))
				{
					if (!IsSearchable(entry)) continue;
					if (!entry.Strings.Exists(FieldCredentialId) || !entry.Strings.Exists(FieldRelyingParty)) continue;

					string material = string.Join("",
						entry.Strings.ReadSafe(FieldCredentialId),
						entry.Strings.ReadSafe(FieldRelyingParty),
						entry.Strings.ReadSafe(FieldUsername),
						entry.Strings.ReadSafe(FieldUserHandle),
						entry.Strings.ReadSafe(PwDefs.TitleField));

					byte[] h = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(material));
					for (int i = 0; i < acc.Length; i++) acc[i] ^= h[i];
					count++;
				}
			}
		}
		return count + ":" + Convert.ToBase64String(acc);
	}

	// Returns only public metadata - no private key material. Used for listing credentials.
	private static PasskeyCredential ExtractCredentialMetadata(PwEntry entry, PwDatabase db)
	{
		bool be = ReadFlag(entry, FieldFlagBe, true);
		return new PasskeyCredential
		{
			CredentialId = entry.Strings.ReadSafe(FieldCredentialId),
			RelyingParty = entry.Strings.ReadSafe(FieldRelyingParty),
			UserHandle = entry.Strings.ReadSafe(FieldUserHandle),
			Username = entry.Strings.ReadSafe(FieldUsername),
			Title = ResolveTitle(entry, db),
			BackupEligible = be,
			BackupState = be && ReadFlag(entry, FieldFlagBs, true), // BS implies BE
		};
	}

	// Absent/unrecognized values fall back to the default (keeps pre-existing entries working).
	private static bool ReadFlag(PwEntry entry, string field, bool defaultValue)
	{
		if (!entry.Strings.Exists(field)) return defaultValue;
		var raw = entry.Strings.ReadSafe(field).Trim();
		if (string.IsNullOrEmpty(raw)) return defaultValue;
		if (raw == "1" || raw.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
		if (raw == "0" || raw.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;
		return defaultValue;
	}

	internal PasskeyCredential ExtractCredential(PwEntry entry, PwDatabase db)
	{
		var credential = ExtractCredentialMetadata(entry, db);

		var pem = entry.Strings.ReadSafe(FieldPrivateKey);
		credential.PrivateKeyPem = pem;

		if (!string.IsNullOrEmpty(pem))
		{
			try { credential.Algorithm = PasskeyKeyHelper.DetectAlgorithm(pem); }
			catch (CryptographicException ex)
			{
				Log.Warn($"Failed to detect passkey algorithm for entry '{credential.Title}': {ex.Message}");
			}
		}

		return credential;
	}

	private static string ResolveTitle(PwEntry entry, PwDatabase db)
	{
		var raw = entry.Strings.ReadSafe(PwDefs.TitleField);
		if (string.IsNullOrEmpty(raw)) return raw;
		return CompileTitle(raw, entry, db);
	}

	private static bool IsSearchable(PwEntry entry)
	{
		var group = entry.ParentGroup;
		while (group != null)
		{
			if (group.EnableSearching.HasValue)
				return group.EnableSearching.Value;
			group = group.ParentGroup;
		}
		return true;
	}

	private PwGroup ResolveTargetGroup(PwDatabase db, KeePassPasskeySettings settings)
	{
		if (settings.NewEntryGroupMode == PasskeyEntryGroupMode.SelectedGroup)
		{
			var selected = GetSelectedGroup();
			if (selected != null && GroupBelongsToDatabase(db, selected))
				return selected;

			Log.Warn("Selected group is unavailable or not in the target database; using the Passkeys group instead",
				nameof(ResolveTargetGroup));
		}

		return GetOrCreatePasskeyGroup(db);
	}

	private PwGroup GetSelectedGroup()
	{
		var mainWindow = _host.MainWindow;
		try
		{
			if (mainWindow.InvokeRequired)
				return (PwGroup)mainWindow.Invoke(new Func<PwGroup>(mainWindow.GetSelectedGroup));
			return mainWindow.GetSelectedGroup();
		}
		catch (Exception ex)
		{
			Log.Warn($"Could not read the selected group: {ex.Message}", nameof(GetSelectedGroup));
			return null;
		}
	}

	private static bool GroupBelongsToDatabase(PwDatabase db, PwGroup group)
	{
		for (var g = group; g != null; g = g.ParentGroup)
			if (g == db.RootGroup) return true;
		return false;
	}

	private PwGroup GetOrCreatePasskeyGroup(PwDatabase db)
	{
		var root = db.RootGroup;

		// 1. Find the Passkeys group by UUID.
		var uuid = new PwUuid(PasskeyGroupUuid.ToByteArray());
		var group = root.FindGroup(uuid, true);
		if (group != null) return group;

		// 2. Fall back to KeePassXC-Browser Passkeys group for compatibility.
		var existingKeePassXcGroup = FindGroupByName(root, KeePassXcPasskeyGroupName);
		if (existingKeePassXcGroup != null) return existingKeePassXcGroup;

		// 3. Create the Passkeys group.
		group = new PwGroup(false, true, PasskeyGroupName, PwIcon.MultiKeys);
		group.Uuid = uuid;
		group.Notes = "Your passkeys. Your accounts.";
		root.AddGroup(group, true);
		return group;
	}

	private static PwGroup FindGroupByName(PwGroup root, string name)
	{
		foreach (var group in root.GetGroups(true))
		{
			if (string.Equals(group.Name, name, StringComparison.Ordinal))
				return group;
		}

		return null;
	}

	private List<PwDatabase> GetSearchDatabases()
	{
		var databases = new List<PwDatabase>();
		foreach (var doc in _host.MainWindow.DocumentManager.Documents)
		{
			if (doc.Database != null && doc.Database.IsOpen)
				databases.Add(doc.Database);
		}

		// Put the active database first
		var active = _host.Database;
		if (active != null && databases.Count > 1)
		{
			int idx = databases.IndexOf(active);
			if (idx > 0)
			{
				databases.RemoveAt(idx);
				databases.Insert(0, active);
			}
		}

		return databases;
	}

	// The database a new passkey will be saved to: the target entry's database, else the chosen/active one.
	private PwDatabase ResolveTargetDatabase(DatabaseInfo target, EntryTargetInfo targetEntry)
	{
		if (targetEntry != null && !string.IsNullOrEmpty(targetEntry.DatabaseId))
		{
			foreach (var db in GetSearchDatabases())
			{
				if (db != null && db.IsOpen
					&& string.Equals(db.RootGroup.Uuid.ToHexString(), targetEntry.DatabaseId, StringComparison.Ordinal))
					return db;
			}
		}
		return ResolveDatabaseOrFallback(target, nameof(ResolveTargetDatabase));
	}

	private PwDatabase ResolveDatabaseOrFallback(DatabaseInfo target, string callerName)
	{
		if (target == null || string.IsNullOrEmpty(target.Id))
			return _host.Database;

		PwDatabase firstMatch = null;
		foreach (var doc in _host.MainWindow.DocumentManager.Documents)
		{
			if (doc.Database?.IsOpen != true) continue;
			if (!string.Equals(doc.Database.RootGroup.Uuid.ToHexString(), target.Id, StringComparison.Ordinal)) continue;

			if (!string.IsNullOrEmpty(target.Name) &&
				string.Equals(doc.Database.Name, target.Name, StringComparison.Ordinal))
				return doc.Database;

			if (firstMatch == null)
				firstMatch = doc.Database;
		}

		if (firstMatch != null) return firstMatch;

		Log.Warn($"Target database {target.Id} not found, falling back to active database", callerName);
		return _host.Database;
	}
}
