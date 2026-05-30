// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Security;
using KeePassPasskey.Passkey;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace KeePassPasskey.Storage
{
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

            entry.Strings.Set(FieldCredentialId, new ProtectedString(true, credential.CredentialId));
            entry.Strings.Set(FieldPrivateKey, new ProtectedString(true, credential.PrivateKeyPem));
            entry.Strings.Set(FieldRelyingParty, new ProtectedString(false, credential.RelyingParty));
            entry.Strings.Set(FieldUserHandle, new ProtectedString(true, credential.UserHandle ?? ""));
            entry.Strings.Set(FieldUsername, new ProtectedString(false, credential.Username ?? ""));
            entry.Strings.Set(FieldFlagBe, new ProtectedString(false, "1"));
            entry.Strings.Set(FieldFlagBs, new ProtectedString(false, "1"));

            if (settings.AddPasskeyTag)
                entry.AddTag(PasskeyTagName);

            var db = ResolveDatabaseOrFallback(target, nameof(CreatePasskeyEntry));
            if (db == null || !db.IsOpen) return false;

            // Title is set after the other fields so placeholders like {USERNAME}/{S:...} can be
            // resolved against the populated entry when ResolveTitlePlaceholders is enabled.
            entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, BuildTitle(settings, credential, entry, db)));

            var targetGroup = GetOrCreatePasskeyGroup(db);
            targetGroup.AddEntry(entry, true);

            _host.MainWindow.BeginInvoke(new MethodInvoker(() =>
            {
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
                if (KeePass.Program.Config.Application.AutoSaveAfterEntryEdit)
                    _host.MainWindow.SaveDatabase(db, null);
            }));

            return true;
        }

        // Builds the entry title from the configured template. {RP_NAME} is passkey-specific data
        // with no backing entry field, so it is always substituted inline (it cannot remain a live
        // KeePass placeholder). Remaining KeePass placeholders are either resolved now or left in
        // place for KeePass to resolve at display time, depending on ResolveTitlePlaceholders.
        private static string BuildTitle(KeePassPasskeySettings settings, PasskeyCredential credential, PwEntry entry, PwDatabase db)
        {
            var template = settings.EntryTitleTemplate;
            if (string.IsNullOrEmpty(template))
                template = "{RP_NAME} (Passkey)";

            var rpName = !string.IsNullOrEmpty(credential.RpName) ? credential.RpName : credential.RelyingParty;
            template = ReplaceIgnoreCase(template, RpNameToken, rpName ?? "");

            if (settings.ResolveTitlePlaceholders)
                return SprEngine.Compile(template, new SprContext(entry, db, SprCompileFlags.Deref));

            return template;
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

        internal bool HasAnyExcludeCredentialForRpId(string rpId, List<string> credentialIds, DatabaseInfo target = null)
        {
            var credIdSet = new HashSet<string>(credentialIds, StringComparer.Ordinal);
            var db = ResolveDatabaseOrFallback(target, nameof(HasAnyExcludeCredentialForRpId));
            if (db == null || !db.IsOpen) return false;

            foreach (var entry in db.RootGroup.GetEntries(true))
            {
                if (!IsSearchable(entry)) continue;
                if (!entry.Strings.Exists(FieldCredentialId)) continue;
                var entryCredId = entry.Strings.ReadSafe(FieldCredentialId);
                if (!credIdSet.Contains(entryCredId)) continue;
                if (!entry.Strings.Exists(FieldRelyingParty)) continue;
                var entryRpId = entry.Strings.ReadSafe(FieldRelyingParty);
                if (string.Equals(entryRpId, rpId, StringComparison.OrdinalIgnoreCase))
                    return true;
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

        // Returns only public metadata - no private key material. Used for listing credentials.
        private static PasskeyCredential ExtractCredentialMetadata(PwEntry entry, PwDatabase db)
        {
            return new PasskeyCredential
            {
                CredentialId = entry.Strings.ReadSafe(FieldCredentialId),
                RelyingParty = entry.Strings.ReadSafe(FieldRelyingParty),
                UserHandle = entry.Strings.ReadSafe(FieldUserHandle),
                Username = entry.Strings.ReadSafe(FieldUsername),
                Title = ResolveTitle(entry, db),
            };
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
            return SprEngine.Compile(raw, new SprContext(entry, db, SprCompileFlags.Deref));
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
}
