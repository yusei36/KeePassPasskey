// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using KeePassPasskeyShared;
using KeePassPasskeyProvider.Authenticator.Native;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Logs a decoded CTAP-CBOR request as one Debug-log line.
/// Debug builds show full buffers and PII; Release redacts to lengths (see DumpBytes/DumpPii).
/// </summary>
internal static unsafe class CtapRequestDump
{
	/// <summary>Logs the request at Debug level. No-op unless Debug logging is enabled.</summary>
	public static void LogRequest(WebAuthnCtapCborMakeCredentialRequest* p, [CallerMemberName] string member = "")
	{
		if (Log.MinLevel <= LogLevel.Debug) Log.Debug(Describe(p), member);
	}

	/// <summary>Logs the request at Debug level. No-op unless Debug logging is enabled.</summary>
	public static void LogRequest(WebAuthnCtapCborGetAssertionRequest* p, [CallerMemberName] string member = "")
	{
		if (Log.MinLevel <= LogLevel.Debug) Log.Debug(Describe(p), member);
	}

	private static string Describe(WebAuthnCtapCborMakeCredentialRequest* p)
	{
		static string Wsz(char* s) => s == null ? "<null>" : new string(s);

		string rp = p->pRpInformation == null ? "<null>"
			: $"{{id={Wsz(p->pRpInformation->pwszId)},name={Wsz(p->pRpInformation->pwszName)}}}";

		string user = "<null>";
		if (p->pUserInformation != null)
		{
			var u = p->pUserInformation;
			user = $"{{id={DumpBytes(u->pbId, u->cbId)},name={DumpPii(u->pwszName)},display={DumpPii(u->pwszDisplayName)}}}";
		}

		var algs = new List<int>();
		for (uint i = 0; i < p->WebAuthNCredentialParameters.cCredentialParameters; i++)
			algs.Add(p->WebAuthNCredentialParameters.pCredentialParameters[i].lAlg);

		string opts = p->pAuthenticatorOptions == null ? "<null>"
			: $"{{up={p->pAuthenticatorOptions->lUp},uv={p->pAuthenticatorOptions->lUv},rk={p->pAuthenticatorOptions->lRequireResidentKey}}}";

		return $"decoded make_credential: ver={p->dwVersion}" +
			$" rpId={Encoding.UTF8.GetString(p->pbRpId, (int)p->cbRpId)}" +
			$" clientDataHash={DumpBytes(p->pbClientDataHash, p->cbClientDataHash)}" +
			$" rp={rp} user={user} algs=[{string.Join(",", algs)}]" +
			$" excludeCount={p->CredentialList.cCredentials}" +
			$" extMap={DumpBytes(p->pbCborExtensionsMap, p->cbCborExtensionsMap)} opts={opts}" +
			$" emptyPinAuth={p->fEmptyPinAuth} pinAuth={DumpBytes(p->pbPinAuth, p->cbPinAuth)} pinProtocol={p->dwPinProtocol}" +
			$" hmacSecretExt={p->lHmacSecretExt} prfExt={p->lPrfExt} hmacSaltValues={DumpBytes(p->pbHmacSecretSaltValues, p->cbHmacSecretSaltValues)}" +
			$" credProtect={p->dwCredProtect} enterpriseAttestation={p->dwEnterpriseAttestation}" +
			$" credBlobExt={DumpBytes(p->pbCredBlobExt, p->cbCredBlobExt)} largeBlobKeyExt={p->lLargeBlobKeyExt} largeBlobSupport={p->dwLargeBlobSupport}" +
			$" minPinLengthExt={p->lMinPinLengthExt} jsonExt={DumpBytes(p->pbJsonExt, p->cbJsonExt)}";
	}

	private static string Describe(WebAuthnCtapCborGetAssertionRequest* p)
	{
		var allow = new List<string>();
		for (uint i = 0; i < p->CredentialList.cCredentials; i++)
		{
			var c = p->CredentialList.ppCredentials[i];
			allow.Add(DumpBytes(c->pbId, c->cbId));
		}

		string opts = p->pAuthenticatorOptions == null ? "<null>"
			: $"{{up={p->pAuthenticatorOptions->lUp},uv={p->pAuthenticatorOptions->lUv},rk={p->pAuthenticatorOptions->lRequireResidentKey}}}";

		return $"decoded get_assertion: ver={p->dwVersion}" +
			$" rpId={Encoding.UTF8.GetString(p->pbRpId, (int)p->cbRpId)}" +
			$" clientDataHash={DumpBytes(p->pbClientDataHash, p->cbClientDataHash)}" +
			$" allow=[{string.Join(",", allow)}]" +
			$" extMap={DumpBytes(p->pbCborExtensionsMap, p->cbCborExtensionsMap)} opts={opts}" +
			$" emptyPinAuth={p->fEmptyPinAuth} pinAuth={DumpBytes(p->pbPinAuth, p->cbPinAuth)} pinProtocol={p->dwPinProtocol}" +
			$" hmacSaltValues={DumpBytes(p->pbHmacSecretSaltValues, p->cbHmacSecretSaltValues)}" +
			$" credBlobExt={p->lCredBlobExt} largeBlobKeyExt={p->lLargeBlobKeyExt}" +
			$" credLargeBlobOp={p->dwCredLargeBlobOperation} credLargeBlob={DumpBytes(p->pbCredLargeBlobCompressed, p->cbCredLargeBlobCompressed)}" +
			$" credLargeBlobOrigSize={p->dwCredLargeBlobOriginalSize} jsonExt={DumpBytes(p->pbJsonExt, p->cbJsonExt)}";
	}

	// Debug: full hex. Release: length only, so shared logs carry no raw crypto/extension bytes.
	private static string DumpBytes(byte* pb, uint cb)
	{
		if (pb == null) return "<null>";
#if DEBUG
		return $"[{cb}]{Convert.ToHexString(new ReadOnlySpan<byte>(pb, (int)cb))}";
#else
		return $"[{cb}]";
#endif
	}

	// Debug: the value. Release: length only, so usernames/emails never land in a shared log.
	private static string DumpPii(char* s)
	{
		if (s == null) return "<null>";
#if DEBUG
		return new string(s);
#else
		int len = new string(s).Length;
		return len == 0 ? "<empty>" : $"<redacted,len={len}>";
#endif
	}
}
