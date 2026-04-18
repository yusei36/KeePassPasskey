using System.Runtime.InteropServices;
using System.Text;
using KeePassPasskey.Shared;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Ipc;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Plugin;

/// <summary>
/// Managed implementation of IPluginAuthenticator.
/// Each COM activation creates one instance; CancelOperation sets m_cancelled.
/// </summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class PluginAuthenticator : IPluginAuthenticator
{
    private volatile bool _cancelled;

    // -----------------------------------------------------------------
    // Helper Methods
    // -----------------------------------------------------------------

    /// <summary>
    /// Verifies the request signature by extracting fields from the request pointer.
    /// </summary>
    private static unsafe int VerifyRequestSignature(WebAuthnPluginOperationRequest* pRequest)
        => SignatureVerifier.VerifyIfKeyAvailable(
            pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
            pRequest->pbRequestSignature, pRequest->cbRequestSignature);

    /// <summary>
    /// Extracts credential IDs from a WebAuthn credential list and converts them to base64url.
    /// </summary>
    private static unsafe List<string> ExtractCredentialIds(WebAuthnCredentialList list)
    {
        var ids = new List<string>((int)list.cCredentials);
        for (uint i = 0; i < list.cCredentials; i++)
        {
            var c = list.ppCredentials[i];
            ids.Add(Base64Url.Encode(new ReadOnlySpan<byte>(c->pbId, (int)c->cbId).ToArray()));
        }
        return ids;
    }

    /// <summary>
    /// Maps error codes from the KeePass plugin response to Windows HRESULTs.
    /// Used by both MakeCredential and GetAssertion.
    /// </summary>
    private static int MapErrorCode(string? code) => code switch
    {
        "db_locked" => PluginConstants.HRESULT_FROM_WIN32_ERROR_LOCK_VIOLATION,
        "duplicate" => PluginConstants.HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS,
        "not_found" => PluginConstants.NTE_NOT_FOUND,
        _           => PluginConstants.E_FAIL,
    };

    /// <summary>
    /// Encodes the attestation response (for make_credential).
    /// Isolates the fixed-pinning block and WebAuthnCredentialAttestation struct construction.
    /// </summary>
    private static unsafe int EncodeAttestation(
        byte[] authData, out uint cbEncoded, out byte* pbEncoded)
    {
        fixed (char* fmtPtr = "none")
        fixed (byte* authPtr = authData)
        {
            var attestation = new WebAuthnCredentialAttestation
            {
                dwVersion            = PluginConstants.AttestationCurrentVersion,
                pwszFormatType       = fmtPtr,
                cbAuthenticatorData  = (uint)authData.Length,
                pbAuthenticatorData  = authPtr,
                cbAttestation        = 0,
                pbAttestation        = null,
            };

            uint cb = 0;
            byte* pb = null;
            int hr = WebAuthnApi.WebAuthNEncodeMakeCredentialResponse(&attestation, &cb, &pb);
            cbEncoded = cb;
            pbEncoded = pb;
            return hr;
        }
    }

    /// <summary>
    /// Encodes the assertion response (for get_assertion).
    /// Isolates the 7-way fixed-pinning block and WebAuthnCtapCborGetAssertionResponse struct construction.
    /// Converts base64/base64url strings to byte arrays internally.
    /// </summary>
    private static unsafe int EncodeAssertion(
        string? authDataB64, string? signatureB64,
        string? credIdB64, string? userHandleB64,
        string? userName, string? userDisplayName,
        out uint cbEncoded, out byte* pbEncoded)
    {
        // Convert base64/base64url strings to byte arrays
        byte[] authDataBytes = Convert.FromBase64String(authDataB64 ?? string.Empty);
        byte[] signatureBytes = Convert.FromBase64String(signatureB64 ?? string.Empty);
        byte[] userHandleBytes = string.IsNullOrEmpty(userHandleB64)
            ? Array.Empty<byte>()
            : Base64Url.Decode(userHandleB64);
        byte[] credIdBytes = string.IsNullOrEmpty(credIdB64)
            ? Array.Empty<byte>()
            : Base64Url.Decode(credIdB64);

        fixed (byte* authPtr = authDataBytes)
        fixed (byte* sigPtr = signatureBytes)
        fixed (byte* uhPtr = userHandleBytes.Length > 0 ? userHandleBytes : new byte[1])
        fixed (byte* credPtr = credIdBytes.Length > 0 ? credIdBytes : new byte[1])
        fixed (char* typePtr = PluginConstants.CredentialTypePublicKey)
        fixed (char* namePtr = userName ?? string.Empty)
        fixed (char* dispPtr = (userDisplayName ?? userName) ?? string.Empty)
        {
            var cred = new WebAuthnCredential
            {
                dwVersion           = PluginConstants.CredentialVersion,
                cbId                = (uint)credIdBytes.Length,
                pbId                = credPtr,
                pwszCredentialType  = typePtr,
            };

            // Build the assertion response struct (full v6 size, zero-initialized)
            var assertionResp = new WebAuthnCtapCborGetAssertionResponse();
            assertionResp.WebAuthNAssertion.dwVersion             = PluginConstants.AssertionCurrentVersion;
            assertionResp.WebAuthNAssertion.Credential            = cred;
            assertionResp.WebAuthNAssertion.cbAuthenticatorData   = (uint)authDataBytes.Length;
            assertionResp.WebAuthNAssertion.pbAuthenticatorData   = authPtr;
            assertionResp.WebAuthNAssertion.cbSignature           = (uint)signatureBytes.Length;
            assertionResp.WebAuthNAssertion.pbSignature           = sigPtr;
            assertionResp.WebAuthNAssertion.cbUserId              = (uint)userHandleBytes.Length;
            assertionResp.WebAuthNAssertion.pbUserId              = userHandleBytes.Length > 0 ? uhPtr : null;
            assertionResp.dwNumberOfCredentials                   = 1;
            assertionResp.lUserSelected                           = 1; // TRUE

            // Build user info if we have a user handle
            WebAuthnUserEntityInformation userInfo = default;
            if (userHandleBytes.Length > 0)
            {
                userInfo.dwVersion     = PluginConstants.UserEntityVersion;
                userInfo.cbId          = (uint)userHandleBytes.Length;
                userInfo.pbId          = uhPtr;
                userInfo.pwszName      = namePtr;
                userInfo.pwszIcon      = null;
                userInfo.pwszDisplayName = dispPtr;
                assertionResp.pUserInformation = &userInfo;
            }

            uint cb = 0;
            byte* pb = null;
            int hr = WebAuthnApi.WebAuthNEncodeGetAssertionResponse(&assertionResp, &cb, &pb);
            cbEncoded = cb;
            pbEncoded = pb;
            return hr;
        }
    }

    // -----------------------------------------------------------------
    // MakeCredential
    // -----------------------------------------------------------------
    public unsafe int MakeCredential(nint pRequestRaw, nint pResponseRaw)
    {
        if (pRequestRaw == 0 || pResponseRaw == 0)
            return PluginConstants.E_INVALIDARG;

        var pRequest  = (WebAuthnPluginOperationRequest*)pRequestRaw;
        var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
        *pResponse = default;

        try
        {
            _cancelled = false;
            Log.Info("entry");

            // 1. Decode CBOR request
            WebAuthnCtapCborMakeCredentialRequest* pDecoded = null;
            int hr1 = WebAuthnApi.WebAuthNDecodeMakeCredentialRequest(
                pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
            Log.Info($"WebAuthNDecodeMakeCredentialRequest hr=0x{hr1:X8}");
            if (hr1 < 0) return hr1;

            try
            {
                // 2. Verify request signature
                int sigResult = VerifyRequestSignature(pRequest);
                Log.Info($"SignatureVerifier hr=0x{sigResult:X8}");
                if (sigResult < 0) return sigResult;

                if (_cancelled) { Log.Info("cancelled"); return PluginConstants.NTE_USER_CANCELLED; }

                // 3. Build JSON request for KeePass
                string rpIdUtf8 = Encoding.UTF8.GetString(pDecoded->pbRpId, (int)pDecoded->cbRpId);
                string userIdB64 = string.Empty;
                string userNameStr = string.Empty;
                string userDisplayStr = string.Empty;
                string rpNameStr = string.Empty;

                if (pDecoded->pUserInformation != null)
                {
                    var u = pDecoded->pUserInformation;
                    if (u->cbId > 0)
                        userIdB64 = Base64Url.Encode(new ReadOnlySpan<byte>(u->pbId, (int)u->cbId).ToArray());
                    if (u->pwszName != null) userNameStr = new string(u->pwszName);
                    if (u->pwszDisplayName != null) userDisplayStr = new string(u->pwszDisplayName);
                }
                if (pDecoded->pRpInformation != null && pDecoded->pRpInformation->pwszName != null)
                    rpNameStr = new string(pDecoded->pRpInformation->pwszName);

                var excludeList = ExtractCredentialIds(pDecoded->CredentialList);

                var req = new IpcRequest
                {
                    Type = "make_credential",
                    RequestId = "mc1",
                    RpId = rpIdUtf8,
                    RpName = rpNameStr,
                    UserId = userIdB64,
                    UserName = userNameStr,
                    UserDisplayName = userDisplayStr,
                    ExcludeCredentials = excludeList,
                };

                // 4. Send to KeePass plugin
                Log.Info($"sending pipe request rpId={rpIdUtf8}");
                if (!PipeClient.SendRequest(req, out var resp) || resp == null)
                {
                    Log.Warn("pipe failed");
                    return PluginConstants.NTE_NOT_FOUND;
                }

                if (resp.Type == "error")
                {
                    Log.Warn($"KeePass error code={resp.Code}");
                    return MapErrorCode(resp.Code);
                }

                // 5. Build authenticatorData and encode attestation response
                var credentialIdBytes = Base64Url.Decode(resp.CredentialId!);
                var ecX = Convert.FromBase64String(resp.PublicKeyX!);
                var ecY = Convert.FromBase64String(resp.PublicKeyY!);
                var authData = AuthenticatorData.BuildForRegistration(rpIdUtf8, PluginConstants.KeePassPasskeyProviderAaguidBytes, credentialIdBytes, ecX, ecY);
                int hrEnc = EncodeAttestation(authData, out uint cbEncoded, out byte* pbEncoded);
                Log.Info($"WebAuthNEncodeMakeCredentialResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                if (hrEnc < 0) return hrEnc;

                pResponse->cbEncodedResponse = cbEncoded;
                pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller (platform frees)

                // 6. Sync Windows autofill cache
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

                Log.Info("success");
                return PluginConstants.S_OK;
            }
            finally
            {
                WebAuthnApi.WebAuthNFreeDecodedMakeCredentialRequest(pDecoded);
            }
        }
        catch (Exception ex)
        {
            Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
            return Marshal.GetHRForException(ex);
        }
    }

    // -----------------------------------------------------------------
    // GetAssertion
    // -----------------------------------------------------------------
    public unsafe int GetAssertion(nint pRequestRaw, nint pResponseRaw)
    {
        if (pRequestRaw == 0 || pResponseRaw == 0)
            return PluginConstants.E_INVALIDARG;

        var pRequest  = (WebAuthnPluginOperationRequest*)pRequestRaw;
        var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
        *pResponse = default;

        try
        {
            _cancelled = false;
            Log.Info("entry");

            // 1. Decode CBOR request
            WebAuthnCtapCborGetAssertionRequest* pDecoded = null;
            int hr1 = WebAuthnApi.WebAuthNDecodeGetAssertionRequest(
                pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
            Log.Info($"WebAuthNDecodeGetAssertionRequest hr=0x{hr1:X8}");
            if (hr1 < 0) return hr1;

            try
            {
                // 2. Verify request signature
                int sigResult = VerifyRequestSignature(pRequest);
                Log.Info($"SignatureVerifier hr=0x{sigResult:X8}");
                if (sigResult < 0) return sigResult;

                if (_cancelled) { Log.Info("cancelled"); return PluginConstants.NTE_USER_CANCELLED; }

                // 3. Extract fields
                string rpIdUtf8 = Encoding.UTF8.GetString(pDecoded->pbRpId, (int)pDecoded->cbRpId);
                string clientDataHashB64 = Convert.ToBase64String(
                    new ReadOnlySpan<byte>(pDecoded->pbClientDataHash, (int)pDecoded->cbClientDataHash).ToArray());

                var allowList = ExtractCredentialIds(pDecoded->CredentialList);

                // 4. Build JSON pipe request
                var req = new IpcRequest
                {
                    Type = "get_assertion",
                    RequestId = "ga1",
                    RpId = rpIdUtf8,
                    ClientDataHash = clientDataHashB64,
                    AllowCredentials = allowList,
                };

                // 5. Send to KeePass plugin
                Log.Info("sending pipe request");
                if (!PipeClient.SendRequest(req, out var resp) || resp == null)
                {
                    Log.Warn("pipe failed");
                    return PluginConstants.NTE_NOT_FOUND;
                }

                if (resp.Type == "error")
                {
                    Log.Warn($"KeePass error code={resp.Code}");
                    return MapErrorCode(resp.Code);
                }

                // 6. Encode assertion response
                int hrEnc = EncodeAssertion(
                    resp.AuthenticatorData, resp.Signature, resp.CredentialId, resp.UserHandle,
                    resp.UserName, resp.UserDisplayName, out uint cbEncoded, out byte* pbEncoded);
                Log.Info($"WebAuthNEncodeGetAssertionResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                if (hrEnc < 0) return hrEnc;

                pResponse->cbEncodedResponse = cbEncoded;
                pResponse->pbEncodedResponse = pbEncoded;

                Log.Info("success");
                return PluginConstants.S_OK;
            }
            finally
            {
                WebAuthnApi.WebAuthNFreeDecodedGetAssertionRequest(pDecoded);
            }
        }
        catch (Exception ex)
        {
            Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
            return Marshal.GetHRForException(ex);
        }
    }

    // -----------------------------------------------------------------
    // CancelOperation
    // -----------------------------------------------------------------
    public int CancelOperation(nint pCancelRequest)
    {
        _cancelled = true;
        return PluginConstants.S_OK;
    }

    // -----------------------------------------------------------------
    // GetLockStatus
    // -----------------------------------------------------------------

    // null = unknown (first call), true = last ping succeeded, false = last ping failed
    private static bool? _lastPingReady;

    public unsafe int GetLockStatus(nint pLockStatusRaw)
    {
        if (pLockStatusRaw == 0) return PluginConstants.E_INVALIDARG;
        var pLockStatus = (PluginLockStatus*)pLockStatusRaw;

        try
        {
            var req = new IpcRequest { Type = "ping", RequestId = "ping" };
            bool ok = PipeClient.SendRequest(req, out var resp);
            bool ready = ok && resp?.Status == "ready";
            Log.Info($"pipeOk={ok} status={resp?.Status} ready={ready}");

            if (ready)
            {
                *pLockStatus = PluginLockStatus.PluginUnlocked;
                if (_lastPingReady != true)
                {
                    Log.Info("reconnected — syncing cache");
                    CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
                }
            }
            else
            {
                *pLockStatus = PluginLockStatus.PluginLocked;
                if (_lastPingReady != false)
                {
                    Log.Info("disconnected — clearing cache");
                    CredentialCache.ClearWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);
                }
            }

            _lastPingReady = ready;
            return PluginConstants.S_OK;
        }
        catch (Exception ex)
        {
            Log.Warn($"exception {ex.Message}");
            *pLockStatus = PluginLockStatus.PluginLocked;
            return PluginConstants.S_OK;
        }
    }
}

/// <summary>
/// IClassFactory implementation. Creates a new PluginAuthenticator per call.
/// </summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
public sealed class ClassFactory : IClassFactory
{
    public int CreateInstance(nint pUnkOuter, in Guid riid, out nint ppvObject)
    {
        ppvObject = 0;
        if (pUnkOuter != 0) return PluginConstants.CLASS_E_NOAGGREGATION;

        var auth = new PluginAuthenticator();
        if (riid == PluginConstants.IID_IPluginAuthenticator ||
            riid == PluginConstants.IID_IUnknown)
        {
            ppvObject = Marshal.GetComInterfaceForObject<PluginAuthenticator, IPluginAuthenticator>(auth);
            return PluginConstants.S_OK;
        }
        return PluginConstants.E_NOINTERFACE;
    }

    public int LockServer(bool fLock)
    {
        // No-op — our process lifecycle is managed by the COM message loop.
        return PluginConstants.S_OK;
    }
}
