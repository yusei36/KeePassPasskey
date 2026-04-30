using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;
using KeePassPasskey.Passkey;
using KeePassPasskey.Shared;
using KeePassPasskey.Shared.Passkey;
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
        private const string PasskeyGroupName = "KeePass Passkeys";
        private const string KeePassXcPasskeyGroupName = "KeePassXC-Browser Passkeys";
        private const string FieldCredentialId = "KPEX_PASSKEY_CREDENTIAL_ID";
        private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
        private const string FieldRelyingParty = "KPEX_PASSKEY_RELYING_PARTY";
        private const string FieldUserHandle = "KPEX_PASSKEY_USER_HANDLE";
        private const string FieldUsername = "KPEX_PASSKEY_USERNAME";
        private const string FieldFlagBe = "KPEX_PASSKEY_FLAG_BE";
        private const string FieldFlagBs = "KPEX_PASSKEY_FLAG_BS";

        private readonly IPluginHost _host;

        internal PasskeyEntryStorage(IPluginHost host)
        {
            _host = host;
        }

        internal bool CreatePasskeyEntry(PasskeyCredential credential)
        {
            var entry = new PwEntry(true, true);
            entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false,
                string.Format("{0} (Passkey)", credential.RpName ?? credential.RelyingParty)));
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

            entry.AddTag("Passkey");

            var db = _host.Database;
            if (db == null || !db.IsOpen) return false;

            var targetGroup = GetOrCreatePasskeyGroup(db);
            targetGroup.AddEntry(entry, true);

            _host.MainWindow.Invoke(new MethodInvoker(() =>
            {
                _host.MainWindow.UpdateUI(false, null, true, null, true, null, true);
                if (KeePass.Program.Config.Application.AutoSaveAfterEntryEdit)
                    _host.MainWindow.SaveDatabase(db, null);
            }));

            return true;
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
                        results.Add(ExtractCredential(entry));
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
                        results.Add(ExtractCredential(entry));
                }
            }
            return results;
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
                        results.Add(ExtractCredential(entry));
                }
            }
            return results;
        }

        internal PasskeyCredential ExtractCredential(PwEntry entry)
        {
            var pem = entry.Strings.ReadSafe(FieldPrivateKey);

            // DetectAlgorithm is best-effort for listing/caching — Sign() does its own detection.
            // A bad PEM on one entry must not abort the whole GetAllCredentials loop.
            PasskeyAlgorithm algorithm = PasskeyAlgorithm.ES256;
            if (!string.IsNullOrEmpty(pem))
            {
                try { algorithm = PasskeyKeyHelper.DetectAlgorithm(pem); }
                catch (CryptographicException ex) 
                { 
                    Log.Warn($"Failed to detect passkey algorithm for entry '{entry.Strings.ReadSafe(PwDefs.TitleField)}': {ex.Message}");
                }
            }

            return new PasskeyCredential
            {
                CredentialId = entry.Strings.ReadSafe(FieldCredentialId),
                PrivateKeyPem = pem,
                RelyingParty = entry.Strings.ReadSafe(FieldRelyingParty),
                UserHandle = entry.Strings.ReadSafe(FieldUserHandle),
                Username = entry.Strings.ReadSafe(FieldUsername),
                Title = entry.Strings.ReadSafe(PwDefs.TitleField),
                Algorithm = algorithm,
            };
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
            // 1. Check if KeePassXC-Browser Passkeys group exists from KeePassXC-Browser -- if so, reuse it.
            var root = db.RootGroup;
            var existingKeePassXcGroup = FindGroupByName(root, KeePassXcPasskeyGroupName);
            if (existingKeePassXcGroup != null) return existingKeePassXcGroup;

            // 2. Otherwise, find or create our own group by UUID.
            var uuid = new PwUuid(PasskeyGroupUuid.ToByteArray());
            var group = root.FindGroup(uuid, true);
            if (group != null) return group;

            group = new PwGroup(false, true, PasskeyGroupName, PwIcon.Folder);
            group.Uuid = uuid;
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
            if (databases.Count == 0 && _host.Database != null && _host.Database.IsOpen)
                databases.Add(_host.Database);
            return databases;
        }
    }
}
