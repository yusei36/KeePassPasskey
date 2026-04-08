using KeePass.Plugins;
using PasskeyWinNative.Passkey;
using PasskeyWinNative.Storage;
using PasskeyWinNative.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PasskeyWinNative.IPC
{
    internal sealed class RequestHandler
    {
        private readonly IPluginHost _host;
        private readonly PasskeyEntryStorage _storage;

        internal RequestHandler(IPluginHost host, PasskeyEntryStorage storage)
        {
            _host = host;
            _storage = storage;
        }

        internal string Handle(string json)
        {
            IpcRequest req;
            try
            {
                req = JsonConvert.DeserializeObject<IpcRequest>(json);
            }
            catch (Exception ex)
            {
                return Error(null, "internal_error", "Failed to parse request: " + ex.Message);
            }

            try
            {
                switch (req.Type)
                {
                    case "ping":         return HandlePing(req);
                    case "get_credentials": return HandleGetCredentials(req);
                    case "make_credential": return HandleMakeCredential(req);
                    case "get_assertion":   return HandleGetAssertion(req);
                    case "cancel":       return HandleCancel(req);
                    default:
                        return Error(req.RequestId, "internal_error", "Unknown request type: " + req.Type);
                }
            }
            catch (Exception ex)
            {
                return Error(req.RequestId, "internal_error", ex.Message);
            }
        }

        private string HandlePing(IpcRequest req)
        {
            string status;
            if (_host.Database == null || !_host.Database.IsOpen)
                status = "no_database";
            else
                status = "ready";

            return JsonConvert.SerializeObject(new IpcResponse
            {
                Type = "ping",
                RequestId = req.RequestId,
                Status = status
            });
        }

        private string HandleGetCredentials(IpcRequest req)
        {
            if (!IsDatabaseOpen())
                return Error(req.RequestId, "db_locked", "No database open");

            var all = _storage.GetAllCredentials();
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

            return JsonConvert.SerializeObject(new IpcResponse
            {
                Type = "get_credentials",
                RequestId = req.RequestId,
                Credentials = infos
            });
        }

        private string HandleMakeCredential(IpcRequest req)
        {
            if (!IsDatabaseOpen())
                return Error(req.RequestId, "db_locked", "No database open");

            if (string.IsNullOrEmpty(req.RpId))
                return Error(req.RequestId, "internal_error", "rpId is required");

            // TODO: excludeCredentials handling is currently disabled.
            // KeePassXC appears to not enforce this check either, allowing users to
            // re-register passkeys for the same RP freely. Uncomment to enforce the
            // WebAuthn spec requirement that prevents duplicate credentials per authenticator.
            //if (req.ExcludeCredentials != null && req.ExcludeCredentials.Count > 0)
            //{
            //    foreach (var excluded in req.ExcludeCredentials)
            //    {
            //        if (_storage.HasCredentialForRpId(req.RpId, excluded))
            //            return Error(req.RequestId, "duplicate", "Credential already exists for this RP");
            //    }
            //}

            // Generate EC P-256 key pair
            byte[] x, y, d;
            EcKeyHelper.GenerateKeyPair(out x, out y, out d);

            // Generate 32-byte random credential ID
            var credentialIdBytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(credentialIdBytes);
            var credentialId = Base64Url.Encode(credentialIdBytes);

            // Build authenticator data
            var authData = AuthenticatorData.BuildForRegistration(req.RpId, credentialIdBytes, x, y, 0);

            // Export private key as PEM (includes public key)
            var pem = EcKeyHelper.ExportPrivateKeyPem(d, x, y);

            // Create KeePass entry
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

            if (!_storage.CreatePasskeyEntry(credential))
                return Error(req.RequestId, "internal_error", "Failed to create KeePass entry");

            var storedCredential = _storage.FindByRpIdAndCredentialId(req.RpId, credentialId);

            return JsonConvert.SerializeObject(new IpcResponse
            {
                Type = "make_credential",
                RequestId = req.RequestId,
                CredentialId = credentialId,
                Title = storedCredential.Title,
                PublicKeyX = Convert.ToBase64String(x),
                PublicKeyY = Convert.ToBase64String(y),
                AuthenticatorData = Convert.ToBase64String(authData)
            });
        }

        private string HandleGetAssertion(IpcRequest req)
        {
            if (!IsDatabaseOpen())
                return Error(req.RequestId, "db_locked", "No database open");

            if (string.IsNullOrEmpty(req.RpId))
                return Error(req.RequestId, "internal_error", "rpId is required");

            if (string.IsNullOrEmpty(req.ClientDataHash))
                return Error(req.RequestId, "internal_error", "clientDataHash is required");

            // Find matching credential
            List<PasskeyCredential> candidates;
            if (req.AllowCredentials != null && req.AllowCredentials.Count > 0)
                candidates = _storage.FindByRpIdAndCredentialIds(req.RpId, req.AllowCredentials);
            else
                candidates = _storage.FindByRpId(req.RpId);

            if (candidates.Count == 0)
                return Error(req.RequestId, "not_found", "No matching credential found for rpId: " + req.RpId);

            // Use first matching credential (platform handles multi-credential selection via autofill UI)
            var credential = candidates[0];

            // Build authenticator data (sign count = 0, not incremented per KeePassXC behavior)
            var authData = AuthenticatorData.BuildForAuthentication(req.RpId, 0);

            // Concatenate authData + clientDataHash for signing
            var clientDataHashBytes = Convert.FromBase64String(req.ClientDataHash);
            var dataToSign = new byte[authData.Length + clientDataHashBytes.Length];
            Array.Copy(authData, 0, dataToSign, 0, authData.Length);
            Array.Copy(clientDataHashBytes, 0, dataToSign, authData.Length, clientDataHashBytes.Length);

            // Sign with private key (returns DER-encoded signature)
            var signature = EcKeyHelper.Sign(credential.PrivateKeyPem, dataToSign);

            return JsonConvert.SerializeObject(new IpcResponse
            {
                Type = "get_assertion",
                RequestId = req.RequestId,
                CredentialId = credential.CredentialId,
                AuthenticatorData = Convert.ToBase64String(authData),
                Signature = Convert.ToBase64String(signature),
                UserHandle = credential.UserHandle ?? ""
            });
        }

        private string HandleCancel(IpcRequest req)
        {
            return JsonConvert.SerializeObject(new IpcResponse
            {
                Type = "cancel",
                RequestId = req.RequestId,
                Status = "acknowledged"
            });
        }

        private bool IsDatabaseOpen()
        {
            foreach (var doc in _host.MainWindow.DocumentManager.Documents)
                if (doc.Database != null && doc.Database.IsOpen) return true;
            return _host.Database != null && _host.Database.IsOpen;
        }

        private static string Error(string requestId, string code, string message)
        {
            return JsonConvert.SerializeObject(new IpcErrorResponse
            {
                RequestId = requestId,
                Code = code,
                Message = message
            });
        }
    }
}
