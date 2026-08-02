// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal sealed class WindowsHelloUserVerifier : IUserVerifier
{
	public UserVerificationMode Mode => UserVerificationMode.WindowsHello;

	public int VerifyForRegistration(RegistrationVerification request, CancellationToken cancellation,
		out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry)
	{
		selectedDatabase = null;
		selectedEntry = null;
		// rpId, not the site-supplied rp.name: this is rendered by Windows' own dialog, and in
		// WindowsHello-only mode it is the only site identification the user ever sees.
		return Verify(request.RequestPtr, request.UserName, request.RpId, request.TransactionId);
	}

	// The platform owns the Hello prompt and tears it down on its own cancel, so the token is unused.
	public int VerifyForSignIn(SignInVerification request, CancellationToken cancellation)
		=> Verify(request.RequestPtr, request.UserName, SignInHint(request), request.TransactionId);

	// Null means no entry was found, blank means the entry has one and it says nothing.
	private static string SignInHint(SignInVerification request) => request.EntryTitle switch
	{
		null => request.RpId,
		var title when string.IsNullOrWhiteSpace(title) => "(no title)",
		var title => title,
	};

	private static unsafe int Verify(nint pRequest, string username, string displayHint, Guid transactionId)
	{
		var ptr = (WebAuthnPluginOperationRequest*)pRequest;
		nint hwnd = ptr->hWnd != 0 ? ptr->hWnd : Win32Native.GetForegroundWindow();
		Log.Info($"hWnd=0x{hwnd:X} username={username} displayHint={displayHint}");

		byte[]? uvKey = SignatureVerifier.GetUserVerificationPublicKey();
		if (uvKey == null)
		{
			Log.Error("UV public key unavailable, rejecting operation");
			return HResults.NTE_BAD_SIGNATURE;
		}

		fixed (char* usernamePin = username.Length > 0 ? username : "\0")
		fixed (char* hintPin = displayHint.Length > 0 ? displayHint : "\0")
		{
			var uvReq = new WebAuthnPluginUserVerificationRequest
			{
				hwnd = hwnd,
				rguidTransactionId = &transactionId,
				pwszUsername = username.Length > 0 ? usernamePin : null,
				pwszDisplayHint = displayHint.Length > 0 ? hintPin : null,
			};

			uint cbResp = 0;
			byte* pbResp = null;
			int hr = WebAuthnPluginApi.WebAuthNPluginPerformUserVerification(&uvReq, &cbResp, &pbResp);
			Log.Info($"WebAuthNPluginPerformUserVerification hr=0x{hr:X8}");

			try
			{
				if (hr < HResults.S_OK) return hr;

				int verifyHr = SignatureVerifier.VerifySignature(
					new ReadOnlySpan<byte>(ptr->pbEncodedRequest, (int)ptr->cbEncodedRequest),
					uvKey,
					new ReadOnlySpan<byte>(pbResp, (int)cbResp));
				Log.Info($"UV signature hr=0x{verifyHr:X8}");
				return verifyHr;
			}
			finally
			{
				if (pbResp != null)
					WebAuthnPluginApi.WebAuthNPluginFreeUserVerificationResponse(pbResp);
			}
		}
	}
}
