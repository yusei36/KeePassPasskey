using KeePass.Plugins;
using KeePassPasskey.Shared;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskey.Passkey;
using KeePassPasskey.Storage;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace KeePassPasskey.Ipc
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
            PipeRequestBase req;
            try
            {
                req = JsonConvert.DeserializeObject<PipeRequestBase>(json);
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="Failed to parse request: " + ex.Message });
            }

            try
            {
                PipeResponseBase response = req switch
                {
                    PingRequest r            => HandlePing(r),
                    GetCredentialsRequest r  => HandleGetCredentials(r),
                    MakeCredentialRequest r  => HandleMakeCredential(r),
                    GetAssertionRequest r    => HandleGetAssertion(r),
                    CancelRequest r          => HandleCancel(r),
                    _ => new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="Unknown request type: " + req.Type }
                };
                return JsonConvert.SerializeObject(response);
            }
            catch (Exception ex)
            {
                return JsonConvert.SerializeObject(new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage =ex.Message });
            }
        }

        private PingResponse HandlePing(PingRequest req)
        {
            return new PingResponse { Status = IsDatabaseOpen() ? PingStatus.Ready : PingStatus.NoDatabase };
        }

        private GetCredentialsResponse HandleGetCredentials(GetCredentialsRequest req)
        {
            if (!IsDatabaseOpen())
                return new GetCredentialsResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage ="No database open" };

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

            return new GetCredentialsResponse { Credentials = infos };
        }

        private MakeCredentialResponse HandleMakeCredential(MakeCredentialRequest req)
        {
            if (!IsDatabaseOpen())
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage ="No database open" };

            if (string.IsNullOrEmpty(req.RpId))
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="rpId is required" };

            // KeePassXC-style excludeCredentials handling: reject registration only
            // when one of the excluded credential IDs already exists for this RP.
            if (req.ExcludeCredentials != null && req.ExcludeCredentials.Count > 0)
            {
                var existingCredentials = _storage.FindByRpIdAndCredentialIds(req.RpId, req.ExcludeCredentials);
                if (existingCredentials.Count > 0)
                    return new MakeCredentialResponse { ErrorCode = PipeErrorCode.Duplicate, ErrorMessage ="Credential already exists for this RP" };
            }

            // Generate EC P-256 key pair
            byte[] x, y, d;
            EcKeyHelper.GenerateKeyPair(out x, out y, out d);

            // Generate 32-byte random credential ID
            var credentialIdBytes = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(credentialIdBytes);
            var credentialId = Base64Url.Encode(credentialIdBytes);

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
                return new MakeCredentialResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="Failed to create KeePass entry" };

            return new MakeCredentialResponse
            {
                CredentialId = credentialId,
                PublicKeyX = Convert.ToBase64String(x),
                PublicKeyY = Convert.ToBase64String(y),
            };
        }

        private GetAssertionResponse HandleGetAssertion(GetAssertionRequest req)
        {
            if (!IsDatabaseOpen())
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.DbLocked, ErrorMessage ="No database open" };

            if (string.IsNullOrEmpty(req.RpId))
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="rpId is required" };

            if (string.IsNullOrEmpty(req.ClientDataHash))
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.InternalError, ErrorMessage ="clientDataHash is required" };

            // Find matching credential
            List<PasskeyCredential> candidates;
            if (req.AllowCredentials != null && req.AllowCredentials.Count > 0)
                candidates = _storage.FindByRpIdAndCredentialIds(req.RpId, req.AllowCredentials);
            else
                candidates = _storage.FindByRpId(req.RpId);

            if (candidates.Count == 0)
                return new GetAssertionResponse { ErrorCode = PipeErrorCode.NotFound, ErrorMessage ="No matching credential found for rpId: " + req.RpId };

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

        private bool IsDatabaseOpen()
        {
            foreach (var doc in _host.MainWindow.DocumentManager.Documents)
                if (doc.Database != null && doc.Database.IsOpen) return true;
            return _host.Database != null && _host.Database.IsOpen;
        }
    }
}
