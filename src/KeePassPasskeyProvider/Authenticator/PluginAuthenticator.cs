// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Text;
using KeePassPasskeyShared;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyProvider.Authenticator.UserVerification;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Managed implementation of IPluginAuthenticator.
/// Each COM activation creates one instance; CancelOperation sets m_cancelled.
/// </summary>
#pragma warning disable CA1725 // "Raw" suffix frees the interface's name for the typed pointer cast from it.
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

		var pRequest = (WebAuthnPluginOperationRequest*)pRequestRaw;
		var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
		*pResponse = default;

		ComActivity.EnterOperation();
		try
		{
			_cancelled = false;
			_currentTransactionId = pRequest->transactionId;
			Log.Info("entry");

			// 1. Decode CBOR request
			WebAuthnCtapCborMakeCredentialRequest* pDecoded = null;
			int hr1 = WebAuthnPluginApi.WebAuthNDecodeMakeCredentialRequest(
				pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
			Log.Info($"WebAuthNDecodeMakeCredentialRequest hr=0x{hr1:X8}");
			if (hr1 < 0) return hr1;

			// TEMP PRF INSTRUMENTATION (remove): logs whether Windows tells us PRF/hmac-secret was
			// requested at registration, and the raw extensions map, to understand the enable
			// handshake. See docs/prf-implementation-plan.md.
			LogPrfMakeShape(pDecoded);

			try
			{
				// 2. Verify request signature
				int sigResult = VerifyRequestSignature(pRequest);
				Log.Info($"SignatureVerifier hr=0x{sigResult:X8}");
				if (sigResult < 0) return sigResult;

				if (_cancelled) { Log.Info("cancelled"); return HResults.NTE_USER_CANCELLED; }

				// 3. Build JSON request for KeePass
				string rpIdUtf8 = Encoding.UTF8.GetString(pDecoded->pbRpId, (int)pDecoded->cbRpId);

				CtapRequestDump.LogRequest(pDecoded);

				// Always return "none"; warn when a site asks for enterprise attestation so a rejection is traceable.
				if (pDecoded->dwEnterpriseAttestation != WebAuthnConstants.EnterpriseAttestationNone)
					Log.Warn($"Relying party {rpIdUtf8} requested enterprise attestation ({pDecoded->dwEnterpriseAttestation}); KeePassPasskey can't provide this and will return none. The site may reject the passkey if enterprise attestation is required.");

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

				// 3b. Check KeePass reachability before prompting for verification.
				int hrReady = CheckKeePassReady("Passkey creation");
				if (hrReady < HResults.S_OK) return hrReady;

				// 3c. Fetch the open databases for the registration toast's database picker.
				var dbResponse = _pipeClient.GetDatabases();
				var databases = dbResponse?.Databases ?? new List<DatabaseInfo>();
				if (databases.Count == 0)
				{
					Log.Warn("no database open");
					Notifier.ShowPipeError("Passkey creation");
					return HResults.E_FAIL;
				}

				var excludeList = ExtractCredentialIds(pDecoded->CredentialList);

				// 3d. Look up candidate entries to save onto, only if that feature is enabled.
				// The offer is made on the registration toast, so it needs the Notification verifier.
				IReadOnlyList<EntryMatchInfo> candidates = Array.Empty<EntryMatchInfo>();
				if (KeePassPasskeySettings.Current.SaveToExistingEntry &&
					KeePassPasskeySettings.Current.RegistrationVerification.HasFlag(UserVerificationMode.Notification))
				{
					var matchResponse = _pipeClient.FindMatchingEntries(new FindMatchingEntriesRequest { RpId = rpIdUtf8 });
					if (matchResponse?.Entries != null && matchResponse.Entries.Count > 0)
						candidates = matchResponse.Entries;
				}

				// 4. User verification
				var (hrUv, targetDatabase, targetEntry) = UserVerifierDispatcher.VerifyForRegistration(
					(nint)pRequest, pRequest->transactionId, rpIdUtf8, rpNameStr, userNameStr, rpNameStr, databases, candidates);
				Log.Info($"UserVerification hr=0x{hrUv:X8} selectedDb={targetDatabase?.Id ?? "(none)"} targetEntry={targetEntry?.EntryUuid ?? "(none)"}");
				if (hrUv < 0) return hrUv;

				var pubKeyCredParams = ExtractPubKeyCredParams(pDecoded->WebAuthNCredentialParameters);

				var request = new MakeCredentialRequest
				{
					RpId = rpIdUtf8,
					RpName = rpNameStr,
					UserId = userIdB64,
					UserName = userNameStr,
					UserDisplayName = userDisplayStr,
					PubKeyCredParams = pubKeyCredParams.Count > 0 ? pubKeyCredParams : null,
					ExcludeCredentials = excludeList,
					TargetDatabase = targetDatabase,
					TargetEntry = targetEntry,
				};

				// 5. Send to KeePass plugin
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
				var authData = AuthenticatorData.BuildForRegistration(rpIdUtf8, AuthenticatorIdentity.EffectiveAaguidBytes, credentialIdBytes, coseKeyBytes, response.BackupEligible, response.BackupState);

				// TEMP PRF PROBE: if the request asked for prf, signal hmac-secret enabled in the
				// authData extensions (CTAP-canonical) and also try the unsigned extension output,
				// to learn which one flips prf.enabled.
				byte[] makeExtMap = ExtractCborExtensionsMap(pDecoded->cbCborExtensionsMap, pDecoded->pbCborExtensionsMap);
				bool prfRequested = PrfProbe.ExtensionsMapRequestsPrf(makeExtMap);
				byte[]? prfRegOutput = prfRequested ? PrfProbe.BuildRegistrationEnabledOutput() : null;
				if (prfRequested)
				{
					authData = PrfProbe.WithHmacSecretRegistrationExtension(authData);
					Log.Info($"PRF: registration authData+hmac-secret ext, authDataHex={Convert.ToHexString(authData)}");
				}
				Log.Info($"PRF: registration unsignedExtOutput={(prfRegOutput != null ? Convert.ToHexString(prfRegOutput) : "(none)")}");

				int hrEnc = EncodeAttestation(authData, prfRegOutput, out uint cbEncoded, out byte* pbEncoded);
				Log.Info($"WebAuthNEncodeMakeCredentialResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
				if (hrEnc < 0) return hrEnc;

				pResponse->cbEncodedResponse = cbEncoded;
				pResponse->pbEncodedResponse = pbEncoded; // ownership transferred to caller (platform frees)

				Log.Info("success");
				return HResults.S_OK;
			}
			finally
			{
				WebAuthnPluginApi.WebAuthNFreeDecodedMakeCredentialRequest(pDecoded);
			}
		}
		catch (Exception ex)
		{
			Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
			return Marshal.GetHRForException(ex);
		}
		finally
		{
			ComActivity.ExitOperation();
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

		var pRequest = (WebAuthnPluginOperationRequest*)pRequestRaw;
		var pResponse = (WebAuthnPluginOperationResponse*)pResponseRaw;
		*pResponse = default;

		ComActivity.EnterOperation();
		try
		{
			_cancelled = false;
			_currentTransactionId = pRequest->transactionId;
			Log.Info("entry");

			// 1. Decode CBOR request
			WebAuthnCtapCborGetAssertionRequest* pDecoded = null;
			int hr1 = WebAuthnPluginApi.WebAuthNDecodeGetAssertionRequest(
				pRequest->cbEncodedRequest, pRequest->pbEncodedRequest, &pDecoded);
			Log.Info($"WebAuthNDecodeGetAssertionRequest hr=0x{hr1:X8}");
			if (hr1 < 0) return hr1;

			// TEMP PRF INSTRUMENTATION (remove after confirming salt delivery form).
			// Logs which of the two salt representations Windows populates and their sizes,
			// to decide whether salts arrive as encrypted CTAP form (pHmacSaltExtension) or
			// decrypted 32-byte values (pbHmacSecretSaltValues). See docs/prf-implementation-plan.md.
			LogPrfSaltShape(pDecoded);

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

				CtapRequestDump.LogRequest(pDecoded);

				var allowList = ExtractCredentialIds(pDecoded->CredentialList);

				// 3b. Check KeePass reachability before prompting for verification.
				int hrReady = CheckKeePassReady("Sign-in");
				if (hrReady < HResults.S_OK) return hrReady;

				// 4. User verification
				CredentialCache.LookupWindowsCache(rpIdUtf8, allowList, out string uvUsername, out string uvDisplayHint);
				Log.Info($"UV cache lookup userName={uvUsername} displayHint={uvDisplayHint}");
				int hrUv = UserVerifierDispatcher.VerifyForSignIn((nint)pRequest, pRequest->transactionId, rpIdUtf8, uvUsername, uvDisplayHint);
				Log.Info($"UserVerification hr=0x{hrUv:X8}");
				if (hrUv < 0) return hrUv;

				// TEMP PRF PROBE: parse the salt(s), HMAC with the fixed probe key, and forward the
				// output to the plugin so it embeds it in the SIGNED authData extensions.
				byte[] getExtMap = ExtractCborExtensionsMap(pDecoded->cbCborExtensionsMap, pDecoded->pbCborExtensionsMap);
				byte[]? prfPayload = PrfProbe.ComputeHmacPayload(getExtMap);
				Log.Info($"PRF: assertion hmacOutput={(prfPayload != null ? Convert.ToHexString(prfPayload) : "(none)")}");

				// 5. Build JSON pipe request
				var request = new GetAssertionRequest
				{
					RpId = rpIdUtf8,
					ClientDataHash = clientDataHashB64,
					AllowCredentials = allowList,
					HmacSecretOutput = prfPayload != null ? Base64Url.Encode(prfPayload) : null,
				};

				// 6. Send to KeePass plugin
				Log.Info("sending pipe request");
				var response = _pipeClient.GetAssertion(request);
				if (response == null)
				{
					Log.Warn("pipe failed");
					Notifier.ShowPipeError("Sign-in");
					return HResults.E_FAIL;
				}

				if (response.ErrorCode != null)
				{
					Log.Warn($"KeePass error code={response.ErrorCode}, message={response.ErrorMessage}");
					Notifier.ShowGetAssertionError(rpIdUtf8, uvUsername, response.ErrorCode, response.ErrorMessage);
					return MapErrorCode(response.ErrorCode);
				}

				// 7. Encode assertion response (authData passes through unchanged; the plugin already
				// embedded and signed the hmac-secret extension).
				int hrEnc = EncodeAssertion(
					response.AuthenticatorData, response.Signature, response.CredentialId, response.UserHandle,
					response.UserName, response.UserDisplayName, null, out uint cbEncoded, out byte* pbEncoded);
				Log.Info($"WebAuthNEncodeGetAssertionResponse hr=0x{hrEnc:X8} cb={cbEncoded}");
				if (hrEnc < 0) return hrEnc;

				pResponse->cbEncodedResponse = cbEncoded;
				pResponse->pbEncodedResponse = pbEncoded;

				Log.Info("success");
				return HResults.S_OK;
			}
			finally
			{
				WebAuthnPluginApi.WebAuthNFreeDecodedGetAssertionRequest(pDecoded);
			}
		}
		catch (Exception ex)
		{
			Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
			return Marshal.GetHRForException(ex);
		}
		finally
		{
			ComActivity.ExitOperation();
		}
	}

	/// <summary>IPluginAuthenticator.CancelOperation implementation. Verifies the cancel signature and sets the cancellation flag.</summary>
	public unsafe int CancelOperation(nint pCancelRequest)
	{
		ComActivity.MarkActivity();
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
	/// Pings the KeePass plugin and reports PluginUnlocked when it responds Ready, otherwise PluginLocked.
	/// </summary>
	public unsafe int GetLockStatus(nint pLockStatusRaw)
	{
		ComActivity.MarkActivity();
		if (pLockStatusRaw == 0) return HResults.E_INVALIDARG;
		var pLockStatus = (PluginLockStatus*)pLockStatusRaw;

		try
		{
			var response = _pipeClient.Ping();
			bool ready = response?.Status == PingStatus.Ready;
			Log.Info($"pipeOk={response != null} status={response?.Status} ready={ready} clientVersion={PipeConstants.Version} serverVersion={response?.Version}");

			_lastPingReady = ready;
			*pLockStatus = ready ? PluginLockStatus.PluginUnlocked : PluginLockStatus.PluginLocked;
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
	/// Pings KeePass to confirm it is reachable with an open database before the user is prompted
	/// for verification, so both MakeCredential and GetAssertion fail fast (with a notification
	/// already shown) instead of verifying first and only then discovering KeePass cannot proceed.
	/// Returns S_OK when ready, otherwise the appropriate failure HRESULT.
	/// </summary>
	/// <param name="operation">Operation name used in the failure notification.</param>
	private int CheckKeePassReady(string operation)
	{
		var ping = _pipeClient.Ping();
		if (ping == null)
		{
			Log.Warn("ping pipe failed");
			Notifier.ShowPipeError(operation);
			return HResults.E_FAIL;
		}

		if (ping.Status == PingStatus.IncompatibleVersion)
		{
			Log.Warn($"version mismatch clientVersion={PipeConstants.Version} serverVersion={ping.Version}");
			Notifier.ShowVersionMismatch(operation, PipeConstants.Version, ping.Version);
			return HResults.E_FAIL;
		}

		if (ping.Status != PingStatus.Ready)
		{
			Log.Warn($"KeePass not ready status={ping.Status}");
			Notifier.ShowPipeError(operation);
			return HResults.E_FAIL;
		}

		return HResults.S_OK;
	}

	/// <summary>
	/// TEMP PRF INSTRUMENTATION (remove after confirming salt delivery form).
	/// Dumps which of the two hmac-secret salt representations Windows populated on a decoded
	/// get_assertion request, and their sizes, so we can tell whether the plugin receives the
	/// encrypted CTAP form (<see cref="WebAuthnCtapCborHmacSaltExtension"/>) or decrypted 32-byte
	/// salt values. See docs/prf-implementation-plan.md "How to confirm cheaply".
	/// </summary>
	private static unsafe void LogPrfSaltShape(WebAuthnCtapCborGetAssertionRequest* pDecoded)
	{
		try
		{
			var ext = pDecoded->pHmacSaltExtension;
			if (ext != null)
			{
				Log.Info($"PRF: pHmacSaltExtension NON-NULL ver={ext->dwVersion} " +
						 $"pKeyAgreement={(ext->pKeyAgreement != null ? "set" : "null")} " +
						 $"cbEncryptedSalt={ext->cbEncryptedSalt} cbSaltAuth={ext->cbSaltAuth}");
			}
			else
			{
				Log.Info("PRF: pHmacSaltExtension NULL");
			}

			Log.Info($"PRF: cbHmacSecretSaltValues={pDecoded->cbHmacSecretSaltValues} " +
					 $"pbHmacSecretSaltValues={(pDecoded->pbHmacSecretSaltValues != null ? "set" : "null")}");

			Log.Info($"PRF: cbCborExtensionsMap={pDecoded->cbCborExtensionsMap} " +
					 $"dwPinProtocol={pDecoded->dwPinProtocol}");

			if (pDecoded->cbCborExtensionsMap > 0 && pDecoded->pbCborExtensionsMap != null)
			{
				var map = new ReadOnlySpan<byte>(pDecoded->pbCborExtensionsMap, (int)pDecoded->cbCborExtensionsMap);
				Log.Info($"PRF: extensionsMap hex={Convert.ToHexString(map)}");
			}
		}
		catch (Exception ex)
		{
			Log.Warn($"PRF: instrumentation failed {ex.GetType().Name}: {ex.Message}");
		}
	}

	/// <summary>
	/// TEMP PRF INSTRUMENTATION (remove). Dumps the PRF/hmac-secret request fields and raw
	/// extensions map on a decoded make_credential request, to understand the registration-side
	/// enable handshake. See docs/prf-implementation-plan.md.
	/// </summary>
	private static unsafe void LogPrfMakeShape(WebAuthnCtapCborMakeCredentialRequest* pDecoded)
	{
		try
		{
			Log.Info($"PRF: lHmacSecretExt={pDecoded->lHmacSecretExt} lPrfExt={pDecoded->lPrfExt} " +
					 $"pHmacSecretMcExtension={(pDecoded->pHmacSecretMcExtension != null ? "set" : "null")} " +
					 $"cbHmacSecretSaltValues={pDecoded->cbHmacSecretSaltValues}");
			Log.Info($"PRF: cbCborExtensionsMap={pDecoded->cbCborExtensionsMap}");
			if (pDecoded->cbCborExtensionsMap > 0 && pDecoded->pbCborExtensionsMap != null)
			{
				var map = new ReadOnlySpan<byte>(pDecoded->pbCborExtensionsMap, (int)pDecoded->cbCborExtensionsMap);
				Log.Info($"PRF: extensionsMap hex={Convert.ToHexString(map)}");
			}
		}
		catch (Exception ex)
		{
			Log.Warn($"PRF: make instrumentation failed {ex.GetType().Name}: {ex.Message}");
		}
	}

	/// <summary>
	/// TEMP PRF PROBE: copies the raw CBOR extensions map (where Windows actually delivers the
	/// `prf` extension) out of a decoded request into a managed array.
	/// </summary>
	private static unsafe byte[] ExtractCborExtensionsMap(uint cb, byte* pb)
		=> cb > 0 && pb != null
			? new ReadOnlySpan<byte>(pb, (int)cb).ToArray()
			: Array.Empty<byte>();

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
		PipeErrorCode.Duplicate => HResults.ERROR_ALREADY_EXISTS,
		PipeErrorCode.NotFound => HResults.NTE_NOT_FOUND,
		PipeErrorCode.UnsupportedAlgorithm => HResults.E_FAIL,
		_ => HResults.E_FAIL,
	};

	/// <summary>
	/// Encodes the attestation response (for make_credential).
	/// Isolates the fixed-pinning block and WebAuthnCredentialAttestation struct construction.
	/// </summary>
	private static unsafe int EncodeAttestation(
		byte[] authData, byte[]? unsignedExtOutputs, out uint cbEncoded, out byte* pbEncoded)
	{
		fixed (char* fmtPtr = "none")
		fixed (byte* authPtr = authData)
		fixed (byte* extPtr = unsignedExtOutputs != null && unsignedExtOutputs.Length > 0 ? unsignedExtOutputs : new byte[1])
		{
			var attestation = new WebAuthnCredentialAttestation
			{
				dwVersion = WebAuthnConstants.AttestationCurrentVersion,
				pwszFormatType = fmtPtr,
				cbAuthenticatorData = (uint)authData.Length,
				pbAuthenticatorData = authPtr,
				cbAttestation = 0,
				pbAttestation = null,
				// TEMP PRF PROBE (remove): force PRF enabled so Windows records the credential as
				// hmac-secret-capable and processes salts at assertion. Lets us observe the salt
				// delivery form before building real storage. See docs/prf-implementation-plan.md.
				bPrfEnabled = 1,
			};

			// TEMP PRF PROBE: registration unsigned extension output (e.g. {"prf":{"enabled":true}}).
			if (unsignedExtOutputs != null && unsignedExtOutputs.Length > 0)
			{
				attestation.cbUnsignedExtensionOutputs = (uint)unsignedExtOutputs.Length;
				attestation.pbUnsignedExtensionOutputs = extPtr;
			}

			uint cb = 0;
			byte* pb = null;
			int hr = WebAuthnPluginApi.WebAuthNEncodeMakeCredentialResponse(&attestation, &cb, &pb);
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
		byte[]? hmacSecretOutput,
		out uint cbEncoded, out byte* pbEncoded)
	{
		// TEMP PRF PROBE: split the raw HMAC payload into first (32) / optional second (32).
		byte[] hmacFirst = hmacSecretOutput != null && hmacSecretOutput.Length >= 32
			? hmacSecretOutput[..32] : Array.Empty<byte>();
		byte[] hmacSecond = hmacSecretOutput != null && hmacSecretOutput.Length >= 64
			? hmacSecretOutput[32..64] : Array.Empty<byte>();
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
		fixed (byte* hmacFirstPtr = hmacFirst.Length > 0 ? hmacFirst : new byte[1])
		fixed (byte* hmacSecondPtr = hmacSecond.Length > 0 ? hmacSecond : new byte[1])
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

			// TEMP PRF PROBE: structured hmac-secret output via WebAuthnAssertion.pHmacSecret.
			WebAuthnHmacSecretSalt hmacSalt = default;
			if (hmacFirst.Length > 0)
			{
				hmacSalt.cbFirst = (uint)hmacFirst.Length;
				hmacSalt.pbFirst = hmacFirstPtr;
				if (hmacSecond.Length > 0)
				{
					hmacSalt.cbSecond = (uint)hmacSecond.Length;
					hmacSalt.pbSecond = hmacSecondPtr;
				}
				assertionResp.WebAuthNAssertion.pHmacSecret = &hmacSalt;
			}

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
			int hr = WebAuthnPluginApi.WebAuthNEncodeGetAssertionResponse(&assertionResp, &cb, &pb);
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
		ComActivity.MarkActivity();
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
		// No-op - our process lifecycle is managed by the COM message loop.
		return HResults.S_OK;
	}
}
#pragma warning restore CA1725
