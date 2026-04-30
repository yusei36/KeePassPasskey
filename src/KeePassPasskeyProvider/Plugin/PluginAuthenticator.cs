using System.Runtime.InteropServices;
using System.Text;
using KeePassPasskey.Shared;
using KeePassPasskeyProvider.Interop;
using KeePassPasskey.Shared.Ipc;
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
    private Guid _currentTransactionId;
    private readonly PipeClient _pipeClient = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)));

    // null = unknown (first call), true = last ping succeeded, false = last ping failed
    private static bool? _lastPingReady;

    /// <summary>
    /// IPluginAuthenticator.MakeCredential implementation.
    /// Decodes the CBOR request, verifies the signature, forwards to KeePass plugin,
    /// and encodes the attestation response.
    /// </summary>
    public unsafe int MakeCredential(nint pRequestRaw, nint pResponseRaw)
    {
        if (pRequestRaw == 0 || pResponseRaw == 0)
            return HResults.E_INVALIDARG;

        var pRequest  = (WebAuthnPluginOperationRequest*)pRequestRaw;
        var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
        *pResponse = default;

        try
        {
            _cancelled = false;
            _currentTransactionId = pRequest->transactionId;
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

                if (_cancelled) { Log.Info("cancelled"); return HResults.NTE_USER_CANCELLED; }

                // 3. User verification via Windows Hello
                if (AppSettings.Current.RequireUserVerificationForRegistration)
                {
                    string uvUsername = pDecoded->pUserInformation != null && pDecoded->pUserInformation->pwszName != null
                        ? new string(pDecoded->pUserInformation->pwszName) : string.Empty;
                    string uvDisplayHint = pDecoded->pRpInformation != null && pDecoded->pRpInformation->pwszName != null
                        ? new string(pDecoded->pRpInformation->pwszName) : string.Empty;
                    int hrUv = PerformUserVerification(pRequest, uvUsername, uvDisplayHint);
                    Log.Info($"PerformUserVerification hr=0x{hrUv:X8}");
                    if (hrUv < 0) return hrUv;
                }

                // 4. Build JSON request for KeePass
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
                var pubKeyCredParams = ExtractPubKeyCredParams(pDecoded->WebAuthNCredentialParameters);

                var request = new MakeCredentialRequest
                {
                    RpId = rpIdUtf8,
                    RpName = rpNameStr,
                    UserId = userIdB64,
                    UserName = userNameStr,
                    UserDisplayName = userDisplayStr,
                    ExcludeCredentials = excludeList,
                    PubKeyCredParams = pubKeyCredParams.Count > 0 ? pubKeyCredParams : null,
                };

                // 4. Send to KeePass plugin
                Log.Info($"sending pipe request rpId={rpIdUtf8}");
                var response = _pipeClient.MakeCredential(request);
                if (response == null)
                {
                    Log.Warn("pipe failed");
                    Notifier.ShowPipeError("Passkey creation");
                    return HResults.E_FAIL;
                }

                if (response.ErrorCode != null)
                {
                    Log.Warn($"KeePass error code={response.ErrorCode}, message={response.ErrorMessage}");
                    Notifier.ShowMakeCredentialError(rpIdUtf8, response.ErrorCode, response.ErrorMessage);
                    return MapErrorCode(response.ErrorCode);
                }

                // 5. Build authenticatorData and encode attestation response
                var credentialIdBytes = Base64Url.Decode(response.CredentialId!);
                var coseKeyBytes = Base64Url.Decode(response.CoseKey!);
                var authData = AuthenticatorData.BuildForRegistration(rpIdUtf8, PluginConstants.KeePassPasskeyProviderAaguidBytes, credentialIdBytes, coseKeyBytes);
                int hrEnc = EncodeAttestation(authData, out uint cbEncoded, out byte* pbEncoded);
                Log.Info($"WebAuthNEncodeMakeCredentialResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                if (hrEnc < 0) return hrEnc;

                pResponse->cbEncodedResponse = cbEncoded;
                pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller (platform frees)

                // 6. Sync Windows autofill cache
                CredentialCache.SyncToWindowsCache(PluginConstants.KeePassPasskeyProviderClsid);

                Log.Info("success");
                return HResults.S_OK;
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

    /// <summary>
    /// IPluginAuthenticator.GetAssertion implementation.
    /// Decodes the CBOR request, verifies the signature, forwards to KeePass plugin,
    /// and encodes the assertion response.
    /// </summary>
    public unsafe int GetAssertion(nint pRequestRaw, nint pResponseRaw)
    {
        if (pRequestRaw == 0 || pResponseRaw == 0)
            return HResults.E_INVALIDARG;

        var pRequest  = (WebAuthnPluginOperationRequest*)pRequestRaw;
        var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
        *pResponse = default;

        try
        {
            _cancelled = false;
            _currentTransactionId = pRequest->transactionId;
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

                if (_cancelled) { Log.Info("cancelled"); return HResults.NTE_USER_CANCELLED; }

                // 3. Extract fields
                string rpIdUtf8 = Encoding.UTF8.GetString(pDecoded->pbRpId, (int)pDecoded->cbRpId);
                string clientDataHashB64 = Convert.ToBase64String(
                    new ReadOnlySpan<byte>(pDecoded->pbClientDataHash, (int)pDecoded->cbClientDataHash).ToArray());

                var allowList = ExtractCredentialIds(pDecoded->CredentialList);

                // 4. Perform user verification via Windows Hello
                if (AppSettings.Current.RequireUserVerificationForSignIn)
                {
                    CredentialCache.LookupWindowsCache(rpIdUtf8, allowList, out string uvUsername, out string uvDisplayHint);
                    Log.Info($"UV cache lookup userName={uvUsername} displayHint={uvDisplayHint}");

                    int hrUv = PerformUserVerification(pRequest, uvUsername, uvDisplayHint);
                    Log.Info($"PerformUserVerification hr=0x{hrUv:X8}");
                    if (hrUv < 0) return hrUv;
                }

                // 5. Build JSON pipe request
                var request = new GetAssertionRequest
                {
                    RpId = rpIdUtf8,
                    ClientDataHash = clientDataHashB64,
                    AllowCredentials = allowList,
                };

                // 6. Send to KeePass plugin
                Log.Info("sending pipe request");
                var response = _pipeClient.GetAssertion(request);
                if (response == null)
                {
                    Log.Warn("pipe failed");
                    Notifier.ShowPipeError("Sign-in");
                    return HResults.NTE_NOT_FOUND;
                }

                if (response.ErrorCode != null)
                {
                    Log.Warn($"KeePass error code={response.ErrorCode}, message={response.ErrorMessage}");
                    Notifier.ShowGetAssertionError(rpIdUtf8, response.ErrorCode, response.ErrorMessage);
                    return MapErrorCode(response.ErrorCode);
                }

                // 7. Encode assertion response
                int hrEnc = EncodeAssertion(
                    response.AuthenticatorData, response.Signature, response.CredentialId, response.UserHandle,
                    response.UserName, response.UserDisplayName, out uint cbEncoded, out byte* pbEncoded);
                Log.Info($"WebAuthNEncodeGetAssertionResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
                if (hrEnc < 0) return hrEnc;

                pResponse->cbEncodedResponse = cbEncoded;
                pResponse->pbEncodedResponse = pbEncoded;

                Log.Info("success");
                return HResults.S_OK;
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

    /// <summary>IPluginAuthenticator.CancelOperation implementation. Verifies the cancel signature and sets the cancellation flag.</summary>
    public unsafe int CancelOperation(nint pCancelRequest)
    {
        if (pCancelRequest == 0) return HResults.E_INVALIDARG;

        var pCancel = (WebAuthnPluginCancelOperationRequest*)pCancelRequest;
        if (pCancel->transactionId != _currentTransactionId)
            return HResults.NTE_NOT_FOUND;

        int sigResult = SignatureVerifier.VerifyIfKeyAvailable(
            (byte*)&pCancel->transactionId, (uint)sizeof(Guid),
            pCancel->pbRequestSignature, pCancel->cbRequestSignature);
        Log.Info($"CancelOperation signature hr=0x{sigResult:X8}");
        if (sigResult < 0) return sigResult;

        _cancelled = true;
        return HResults.S_OK;
    }

    /// <summary>
    /// IPluginAuthenticator.GetLockStatus implementation.
    /// Pings the KeePass plugin to determine lock status and syncs the Windows credential cache.
    /// </summary>
    public unsafe int GetLockStatus(nint pLockStatusRaw)
    {
        if (pLockStatusRaw == 0) return HResults.E_INVALIDARG;
        var pLockStatus = (PluginLockStatus*)pLockStatusRaw;

        try
        {
            var response = _pipeClient.Ping();
            bool ready = response?.Status == PingStatus.Ready;
            Log.Info($"pipeOk={response != null} status={response?.Status} ready={ready} clientVersion={PipeConstants.Version} serverVersion={response?.Version}");

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
            return HResults.S_OK;
        }
        catch (Exception ex)
        {
            Log.Warn($"exception {ex.Message}");
            *pLockStatus = PluginLockStatus.PluginLocked;
            return HResults.S_OK;
        }
    }

    /// <summary>
    /// Calls WebAuthNPluginPerformUserVerification (Windows Hello prompt).
    /// username and displayHint are passed as hints; either may be empty.
    /// </summary>
    private static unsafe int PerformUserVerification(
        WebAuthnPluginOperationRequest* pRequest, string username, string displayHint)
    {
        nint hwnd = pRequest->hWnd != 0 ? pRequest->hWnd : Win32Native.GetForegroundWindow();
        Log.Info($"hWnd=0x{hwnd:X} username={username} displayHint={displayHint}");

        Guid transactionId = pRequest->transactionId; // stack copy; &transactionId is stable (no fixed needed)
        fixed (char* usernamePin = username.Length > 0 ? username : "\0")
        fixed (char* hintPin = displayHint.Length > 0 ? displayHint : "\0")
        {
            var uvReq = new WebAuthnPluginUserVerificationRequest
            {
                hWnd               = hwnd,
                rguidTransactionId = &transactionId,
                pwszUsername       = username.Length > 0    ? usernamePin : null,
                pwszDisplayHint    = displayHint.Length > 0 ? hintPin     : null,
            };

            uint cbResp = 0;
            byte* pbResp = null;
            int hr = WebAuthnPluginApi.WebAuthNPluginPerformUserVerification(&uvReq, &cbResp, &pbResp);
            Log.Info($"WebAuthNPluginPerformUserVerification hr=0x{hr:X8}");
            if (pbResp != null)
                WebAuthnPluginApi.WebAuthNPluginFreeUserVerificationResponse(pbResp);
            return hr;
        }
    }

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
    /// Extracts COSE algorithm IDs from the RP's pubKeyCredParams list.
    /// </summary>
    private static unsafe List<int> ExtractPubKeyCredParams(WebAuthnCoseCredentialParameters credParams)
    {
        var algs = new List<int>((int)credParams.cCredentialParameters);
        for (uint i = 0; i < credParams.cCredentialParameters; i++)
            algs.Add(credParams.pCredentialParameters[i].lAlg);
        return algs;
    }

    /// <summary>
    /// Maps error codes from the KeePass plugin response to Windows HRESULTs.
    /// Used by both MakeCredential and GetAssertion.
    /// </summary>
    private static int MapErrorCode(PipeErrorCode? code) => code switch
    {
        PipeErrorCode.DbLocked => HResults.E_FAIL,
        PipeErrorCode.Duplicate => HResults.HRESULT_FROM_WIN32_ERROR_ALREADY_EXISTS,
        PipeErrorCode.NotFound => HResults.NTE_NOT_FOUND,
        PipeErrorCode.UnsupportedAlgorithm => HResults.E_FAIL,
        _ => HResults.E_FAIL,
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
                dwVersion = WebAuthnConstants.AttestationCurrentVersion,
                pwszFormatType = fmtPtr,
                cbAuthenticatorData = (uint)authData.Length,
                pbAuthenticatorData = authPtr,
                cbAttestation = 0,
                pbAttestation = null,
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
        fixed (char* typePtr = WebAuthnConstants.CredentialTypePublicKey)
        fixed (char* namePtr = userName ?? string.Empty)
        fixed (char* dispPtr = (userDisplayName ?? userName) ?? string.Empty)
        {
            var cred = new WebAuthnCredential
            {
                dwVersion = WebAuthnConstants.CredentialVersion,
                cbId = (uint)credIdBytes.Length,
                pbId = credPtr,
                pwszCredentialType = typePtr,
            };

            // Build the assertion response struct (full v6 size, zero-initialized)
            var assertionResp = new WebAuthnCtapCborGetAssertionResponse();
            assertionResp.WebAuthNAssertion.dwVersion = WebAuthnConstants.AssertionCurrentVersion;
            assertionResp.WebAuthNAssertion.Credential = cred;
            assertionResp.WebAuthNAssertion.cbAuthenticatorData = (uint)authDataBytes.Length;
            assertionResp.WebAuthNAssertion.pbAuthenticatorData = authPtr;
            assertionResp.WebAuthNAssertion.cbSignature = (uint)signatureBytes.Length;
            assertionResp.WebAuthNAssertion.pbSignature = sigPtr;
            assertionResp.WebAuthNAssertion.cbUserId = (uint)userHandleBytes.Length;
            assertionResp.WebAuthNAssertion.pbUserId = userHandleBytes.Length > 0 ? uhPtr : null;
            assertionResp.dwNumberOfCredentials = 1;
            assertionResp.lUserSelected = 1; // TRUE

            // Build user info if we have a user handle
            WebAuthnUserEntityInformation userInfo = default;
            if (userHandleBytes.Length > 0)
            {
                userInfo.dwVersion = WebAuthnConstants.UserEntityVersion;
                userInfo.cbId = (uint)userHandleBytes.Length;
                userInfo.pbId = uhPtr;
                userInfo.pwszName = namePtr;
                userInfo.pwszIcon = null;
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
        if (pUnkOuter != 0) return HResults.CLASS_E_NOAGGREGATION;

        var auth = new PluginAuthenticator();
        if (riid == ComIids.IID_IPluginAuthenticator ||
            riid == ComIids.IID_IUnknown)
        {
            ppvObject = Marshal.GetComInterfaceForObject<PluginAuthenticator, IPluginAuthenticator>(auth);
            return HResults.S_OK;
        }
        return HResults.E_NOINTERFACE;
    }

    public int LockServer(bool fLock)
    {
        // No-op — our process lifecycle is managed by the COM message loop.
        return HResults.S_OK;
    }
}
