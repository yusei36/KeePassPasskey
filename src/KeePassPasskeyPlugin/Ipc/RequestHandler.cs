// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Passkey;
using KeePassPasskey.Storage;
using KeePassPasskey.Passkey;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace KeePassPasskey.Ipc
{
    internal sealed class RequestHandler
    {
        private static readonly PasskeyAlgorithm[] SupportedAlgorithmsByPriority =
            { PasskeyAlgorithm.ES256, PasskeyAlgorithm.EdDSA, PasskeyAlgorithm.RS256 };

        private readonly IPluginHost _host;
        private readonly PasskeyEntryStorage _passkeyStorage;
        private readonly SettingsStorage _settingsStorage;

        internal RequestHandler(IPluginHost host, PasskeyEntryStorage passkeyStorage, SettingsStorage settingsStorage)
        {
            _host = host;
            _passkeyStorage = passkeyStorage;
            _settingsStorage = settingsStorage;
        }

        internal string Handle(string json)
        {
            PipeRequestBase req;
            try
            {
                req = JsonConvert.DeserializeObject<PipeRequestBase>(json);
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "Failed to parse request: " + ex.Message });
            }

            try
            {
                PipeResponseBase response = req switch
                {
                    PingRequest r           => HandlePing(r),
                    GetCredentialsRequest r => HandleGetCredentials(r),
                    GetDatabasesRequest r   => HandleGetDatabases(r),
                    MakeCredentialRequest r => HandleMakeCredential(r),
                    GetAssertionRequest r   => HandleGetAssertion(r),
                    CancelRequest r         => HandleCancel(r),
                    GetSettingsRequest r    => HandleGetSettings(r),
                    SaveSettingsRequest r   => HandleSaveSettings(r),
                    _ => new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "Unknown request type: " + req.Type }
                };
                return JsonConvert.SerializeObject(response);
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = ex.Message });
            }
        }

        private PingResponse HandlePing(PingRequest req)
        {
            if (req.Version != PipeConstants.Version)
                return new PingResponse { Status = PingStatus.IncompatibleVersion };

            return new PingResponse { Status = IsDatabaseOpen() ? PingStatus.Ready : PingStatus.NoDatabase };
        }

        private GetCredentialsResponse HandleGetCredentials(GetCredentialsRequest req)
        {
            if (!IsDatabaseOpen())
                return new GetCredentialsResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage = "No database open" };

            var all = _passkeyStorage.GetAllCredentials();
            var infos = new List<CredentialInfo>(all.Count);
            foreach (var c in all)
            {
                if (!string.IsNullOrEmpty(req.RpId) && c.RelyingParty != req.RpId)
                    continue;
                if (req.AllowCredentials != null && req.AllowCredentials.Count > 0
                    && !req.AllowCredentials.Contains(c.CredentialId))
                    continue;

                infos.Add(new CredentialInfo
                {
                    CredentialId = c.CredentialId,
                    RpId = c.RelyingParty,
                    UserHandle = c.UserHandle,
                    UserName = c.Username,
                    Title = c.Title
                });
            }

            return new GetCredentialsResponse { Credentials = infos };
        }

        private GetDatabasesResponse HandleGetDatabases(GetDatabasesRequest req)
        {
            var databases = new List<DatabaseInfo>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var doc in _host.MainWindow.DocumentManager.Documents)
            {
                if (doc.Database == null || !doc.Database.IsOpen) continue;
                var info = MakeDatabaseInfo(doc.Database);
                if (!seen.Add(info.Id))
                {
                    Log.Warn($"Two open databases share the same root group UUID ({info.Id}); only the first will be shown in the picker");
                    continue;
                }
                databases.Add(info);
            }
            if (databases.Count == 0 && _host.Database?.IsOpen == true)
                databases.Add(MakeDatabaseInfo(_host.Database));
            return new GetDatabasesResponse { Databases = databases };
        }

        private static DatabaseInfo MakeDatabaseInfo(KeePassLib.PwDatabase db)
        {
            string id = db.RootGroup.Uuid.ToHexString();
            string name = db.Name;
            return new DatabaseInfo { Id = id, Name = string.IsNullOrEmpty(name) ? "(unnamed)" : name };
        }

        private MakeCredentialResponse HandleMakeCredential(MakeCredentialRequest req)
        {
            if (!IsDatabaseOpen())
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage = "No database open" };

            if (string.IsNullOrEmpty(req.RpId))
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "rpId is required" };

            // KeePassXC-style excludeCredentials: reject if any excluded credential exists for this RP
            // Only check the target database to allow users to create credentials in different DBs
            if (req.ExcludeCredentials != null && req.ExcludeCredentials.Count > 0)
            {
                if (_passkeyStorage.HasAnyExcludeCredentialForRpId(req.RpId, req.ExcludeCredentials, req.TargetDatabaseId))
                    return new MakeCredentialResponse { ErrorCode = PipeErrorCode.Duplicate, ErrorMessage = "Credential already exists for this RP" };
            }

            // Algorithm selection: ES256 > EdDSA > RS256, intersected with RP preference
            var chosenAlg = SelectAlgorithm(req.PubKeyCredParams);
            if (chosenAlg == null)
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.UnsupportedAlgorithm, ErrorMessage = "No supported algorithm in pubKeyCredParams" };

            // Generate key pair and COSE key
            var (pem, pubComponents) = PasskeyKeyHelper.GenerateKeyPair(chosenAlg.Value);
            var coseKeyBytes = PasskeyKeyHelper.BuildCoseKey(chosenAlg.Value, pubComponents);

            // Generate 32-byte random credential ID
            var credentialIdBytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(credentialIdBytes);
            var credentialId = Base64Url.Encode(credentialIdBytes);

            var credential = new PasskeyCredential
            {
                CredentialId = credentialId,
                PrivateKeyPem = pem,
                RelyingParty = req.RpId,
                RpName = req.RpName,
                UserHandle = req.UserId ?? "",
                Username = req.UserName ?? "",
                Origin = string.IsNullOrEmpty(req.RpId) ? "" : "https://" + req.RpId
            };

            if (!_passkeyStorage.CreatePasskeyEntry(credential, req.TargetDatabaseId))
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "Failed to create KeePass entry" };

            return new MakeCredentialResponse
            {
                CredentialId = credentialId,
                CoseKey = Base64Url.Encode(coseKeyBytes),
            };
        }

        private GetAssertionResponse HandleGetAssertion(GetAssertionRequest req)
        {
            if (!IsDatabaseOpen())
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage = "No database open" };

            if (string.IsNullOrEmpty(req.RpId))
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "rpId is required" };

            if (string.IsNullOrEmpty(req.ClientDataHash))
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "clientDataHash is required" };

            // Find matching credential
            List<PasskeyCredential> candidates;
            if (req.AllowCredentials != null && req.AllowCredentials.Count > 0)
                candidates = _passkeyStorage.FindByRpIdAndCredentialIds(req.RpId, req.AllowCredentials);
            else
                candidates = _passkeyStorage.FindByRpId(req.RpId);

            if (candidates.Count == 0)
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.NotFound, ErrorMessage = "No matching credential found for rpId: " + req.RpId };

            var credential = candidates[0];

            var authData = AuthenticatorData.BuildForAuthentication(req.RpId, 0);

            var clientDataHashBytes = Convert.FromBase64String(req.ClientDataHash);
            var dataToSign = new byte[authData.Length + clientDataHashBytes.Length];
            Array.Copy(authData, 0, dataToSign, 0, authData.Length);
            Array.Copy(clientDataHashBytes, 0, dataToSign, authData.Length, clientDataHashBytes.Length);
            
            // Sign with private key
            var signature = PasskeyKeyHelper.Sign(credential.PrivateKeyPem, dataToSign);

            return new GetAssertionResponse
            {
                CredentialId = credential.CredentialId,
                AuthenticatorData = Convert.ToBase64String(authData),
                Signature = Convert.ToBase64String(signature),
                UserHandle = credential.UserHandle ?? "",
                UserName = credential.Username ?? "",
                UserDisplayName = string.IsNullOrEmpty(credential.Title) ? (credential.Username ?? "") : credential.Title
            };
        }

        private CancelResponse HandleCancel(CancelRequest req)
        {
            return new CancelResponse { Status = "acknowledged" };
        }

        private GetSettingsResponse HandleGetSettings(GetSettingsRequest req)
        {
            return new GetSettingsResponse { Settings = _settingsStorage.Load() };
        }

        private SaveSettingsResponse HandleSaveSettings(SaveSettingsRequest req)
        {
            _settingsStorage.Save(req.Settings);
            Log.Configure(Log.LogFilePath, req.Settings.LogLevel);
            return new SaveSettingsResponse();
        }

        private bool IsDatabaseOpen()
        {
            foreach (var doc in _host.MainWindow.DocumentManager.Documents)
                if (doc.Database != null && doc.Database.IsOpen) return true;
            return _host.Database != null && _host.Database.IsOpen;
        }

        private static PasskeyAlgorithm? SelectAlgorithm(List<int> pubKeyCredParams)
        {
            if (pubKeyCredParams == null || pubKeyCredParams.Count == 0)
                return PasskeyAlgorithm.ES256;

            var requested = new HashSet<int>(pubKeyCredParams);
            foreach (var alg in SupportedAlgorithmsByPriority)
            {
                if (requested.Contains((int)alg))
                    return alg;
            }
            return null;
        }
    }
}
