using System.Runtime.InteropServices;
using System.Text;
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
            Log.Write("MakeCredential: entry");

            // 1. Decode CBOR request
            WebAuthnCtapCborMakeCredentialRequest* pDecoded = null;
            int hr1 = WebAuthnApi.WebAuthNDecodeMakeCredentialRequest(
                pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
            Log.Write($"MakeCredential: WebAuthNDecodeMakeCredentialRequest hr=0x{hr1:X8}");
            if (hr1 < 0) return hr1;

            try
            {
                // 2. Verify request signature
                var sigResult = SignatureVerifier.VerifyIfKeyAvailable(
                    pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                    pRequest->pbRequestSignature, pRequest->cbRequestSignature);
                Log.Write($"MakeCredential: SignatureVerifier hr=0x{sigResult:X8}");
                if (sigResult < 0) return sigResult;

                if (_cancelled) { Log.Write("MakeCredential: cancelled"); return PluginConstants.NTE_USER_CANCELLED; }

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
                        userIdB64 = Base64Url.Encode(new ReadOnlySpan<byte>(u->pbId, (int)u->cbId));
                    if (u->pwszName != null) userNameStr = new string(u->pwszName);
                    if (u->pwszDisplayName != null) userDisplayStr = new string(u->pwszDisplayName);
                }
                if (pDecoded->pRpInformation != null && pDecoded->pRpInformation->pwszName != null)
                    rpNameStr = new string(pDecoded->pRpInformation->pwszName);

                var excludeList = new List<string>();
                for (uint i = 0; i < pDecoded->CredentialList.cCredentials; i++)
                {
                    var c = pDecoded->CredentialList.ppCredentials[i];
                    excludeList.Add(Base64Url.Encode(new ReadOnlySpan<byte>(c->pbId, (int)c->cbId)));
                }

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
                Log.Write($"MakeCredential: sending pipe request rpId={rpIdUtf8}");
                if (!PipeClient.SendRequest(req, out var resp) || resp == null)
                {
                    Log.Write("MakeCredential: pipe failed");
                    return PluginConstants.NTE_NOT_FOUND;
                }

                if (resp.Type == "error")
                {
                    Log.Write($"MakeCredential: KeePass error code={resp.Code}");
                    return resp.Code switch
                    {
                        "db_locked"  => PluginConstants.HRESULT_FROM_WIN32_ERROR_LOCK_VIOLATION,
                        "duplicate"  => PluginConstants.HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS,
                        "not_found"  => PluginConstants.NTE_NOT_FOUND,
                        _            => PluginConstants.E_FAIL,
                    };
                }

                // 5. Parse response
                string? credIdB64   = resp.CredentialId;
                string? authDataB64 = resp.AuthenticatorData;
                if (string.IsNullOrEmpty(credIdB64) || string.IsNullOrEmpty(authDataB64))
                {
                    Log.Write("MakeCredential: missing credentialId or authenticatorData");
                    return PluginConstants.E_FAIL;
                }

                byte[] authDataBytes = Convert.FromBase64String(authDataB64);
                Log.Write($"MakeCredential: authData={authDataBytes.Length}B credId={credIdB64.Length}ch");

                // 6. Encode attestation response
                // "none" format attestation — we pin the constant string and the authData bytes
                fixed (char* fmtPtr = "none")
                fixed (byte* authPtr = authDataBytes)
                {
                    var attestation = new WebAuthnCredentialAttestation
                    {
                        dwVersion          = PluginConstants.AttestationCurrentVersion,
                        pwszFormatType     = fmtPtr,
                        cbAuthenticatorData = (uint)authDataBytes.Length,
                        pbAuthenticatorData = authPtr,
                        cbAttestation      = 0,
                        pbAttestation      = null,
                    };

                    uint cbEncoded = 0;
                    byte* pbEncoded = null;
                    int hrEnc = WebAuthnApi.WebAuthNEncodeMakeCredentialResponse(&attestation, &cbEncoded, &pbEncoded);
                    Log.Write($"MakeCredential: WebAuthNEncodeMakeCredentialResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                    if (hrEnc < 0) return hrEnc;

                    pResponse->cbEncodedResponse = cbEncoded;
                    pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller (platform frees)
                }

                // 7. Sync Windows autofill cache
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassClsid);

                Log.Write("MakeCredential: success");
                return PluginConstants.S_OK;
            }
            finally
            {
                WebAuthnApi.WebAuthNFreeDecodedMakeCredentialRequest(pDecoded);
            }
        }
        catch (Exception ex)
        {
            Log.Write($"MakeCredential: exception {ex.GetType().Name}: {ex.Message}");
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
            Log.Write("GetAssertion: entry");

            // 1. Decode CBOR request
            WebAuthnCtapCborGetAssertionRequest* pDecoded = null;
            int hr1 = WebAuthnApi.WebAuthNDecodeGetAssertionRequest(
                pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
            Log.Write($"GetAssertion: WebAuthNDecodeGetAssertionRequest hr=0x{hr1:X8}");
            if (hr1 < 0) return hr1;

            try
            {
                // 2. Verify request signature
                var sigResult = SignatureVerifier.VerifyIfKeyAvailable(
                    pRequest->pbEncodedRequest, pRequest->cbEncodedRequest,
                    pRequest->pbRequestSignature, pRequest->cbRequestSignature);
                Log.Write($"GetAssertion: SignatureVerifier hr=0x{sigResult:X8}");
                if (sigResult < 0) return sigResult;

                if (_cancelled) { Log.Write("GetAssertion: cancelled"); return PluginConstants.NTE_USER_CANCELLED; }

                // 3. Extract fields
                string rpIdUtf8 = Encoding.UTF8.GetString(pDecoded->pbRpId, (int)pDecoded->cbRpId);
                string clientDataHashB64 = Convert.ToBase64String(
                    new ReadOnlySpan<byte>(pDecoded->pbClientDataHash, (int)pDecoded->cbClientDataHash).ToArray());

                var allowList = new List<string>();
                for (uint i = 0; i < pDecoded->CredentialList.cCredentials; i++)
                {
                    var c = pDecoded->CredentialList.ppCredentials[i];
                    allowList.Add(Base64Url.Encode(new ReadOnlySpan<byte>(c->pbId, (int)c->cbId)));
                }
                Log.Write($"GetAssertion: rpId={rpIdUtf8} allowCredentials={allowList.Count}");

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
                Log.Write("GetAssertion: sending pipe request");
                if (!PipeClient.SendRequest(req, out var resp) || resp == null)
                {
                    Log.Write("GetAssertion: pipe failed");
                    return PluginConstants.NTE_NOT_FOUND;
                }

                if (resp.Type == "error")
                {
                    Log.Write($"GetAssertion: KeePass error code={resp.Code}");
                    return resp.Code switch
                    {
                        "db_locked" => PluginConstants.HRESULT_FROM_WIN32_ERROR_LOCK_VIOLATION,
                        "not_found" => PluginConstants.NTE_NOT_FOUND,
                        _           => PluginConstants.E_FAIL,
                    };
                }

                // 6. Parse response
                string? authDataB64   = resp.AuthenticatorData;
                string? signatureB64  = resp.Signature;
                string? credIdB64     = resp.CredentialId;
                string? userHandleB64 = resp.UserHandle;
                string? userNameStr   = resp.UserName;
                string? userDispStr   = resp.UserDisplayName;

                if (string.IsNullOrEmpty(authDataB64) || string.IsNullOrEmpty(signatureB64))
                {
                    Log.Write("GetAssertion: missing authData or signature");
                    return PluginConstants.E_FAIL;
                }

                byte[] authDataBytes  = Convert.FromBase64String(authDataB64);
                byte[] signatureBytes = Convert.FromBase64String(signatureB64);
                byte[] userHandleBytes = string.IsNullOrEmpty(userHandleB64)
                    ? Array.Empty<byte>()
                    : Base64Url.Decode(userHandleB64);
                byte[] credIdBytes = string.IsNullOrEmpty(credIdB64)
                    ? Array.Empty<byte>()
                    : Base64Url.Decode(credIdB64);

                Log.Write($"GetAssertion: authData={authDataBytes.Length}B sig={signatureBytes.Length}B credId={credIdBytes.Length}B");

                // 7. Encode assertion response — pin all buffers
                fixed (byte* authPtr  = authDataBytes)
                fixed (byte* sigPtr   = signatureBytes)
                fixed (byte* uhPtr    = userHandleBytes.Length > 0 ? userHandleBytes : new byte[1])
                fixed (byte* credPtr  = credIdBytes.Length > 0 ? credIdBytes : new byte[1])
                fixed (char* typePtr  = PluginConstants.CredentialTypePublicKey)
                fixed (char* namePtr  = userNameStr ?? string.Empty)
                fixed (char* dispPtr  = (userDispStr ?? userNameStr) ?? string.Empty)
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

                    uint cbEncoded = 0;
                    byte* pbEncoded = null;
                    Log.Write("GetAssertion: calling WebAuthNEncodeGetAssertionResponse");
                    int hrEnc = WebAuthnApi.WebAuthNEncodeGetAssertionResponse(&assertionResp, &cbEncoded, &pbEncoded);
                    Log.Write($"GetAssertion: WebAuthNEncodeGetAssertionResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                    if (hrEnc < 0) return hrEnc;

                    pResponse->cbEncodedResponse = cbEncoded;
                    pResponse->pbEncodedResponse = pbEncoded;
                }

                Log.Write("GetAssertion: success");
                return PluginConstants.S_OK;
            }
            finally
            {
                WebAuthnApi.WebAuthNFreeDecodedGetAssertionRequest(pDecoded);
            }
        }
        catch (Exception ex)
        {
            Log.Write($"GetAssertion: exception {ex.GetType().Name}: {ex.Message}");
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
    public unsafe int GetLockStatus(nint pLockStatusRaw)
    {
        if (pLockStatusRaw == 0) return PluginConstants.E_INVALIDARG;
        var pLockStatus = (PluginLockStatus*)pLockStatusRaw;

        try
        {
            var req = new IpcRequest { Type = "ping", RequestId = "ping" };
            bool ok = PipeClient.SendRequest(req, out var resp);
            Log.Write($"GetLockStatus: pipeOk={ok} status={resp?.Status}");

            if (!ok || resp == null)
                *pLockStatus = PluginLockStatus.PluginLocked;
            else if (resp.Status == "ready")
                *pLockStatus = PluginLockStatus.PluginUnlocked;
            else
                *pLockStatus = PluginLockStatus.PluginLocked;

            return PluginConstants.S_OK;
        }
        catch (Exception ex)
        {
            Log.Write($"GetLockStatus: exception {ex.Message}");
            *pLockStatus = PluginLockStatus.PluginLocked;
            return PluginConstants.S_OK; // non-fatal
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
