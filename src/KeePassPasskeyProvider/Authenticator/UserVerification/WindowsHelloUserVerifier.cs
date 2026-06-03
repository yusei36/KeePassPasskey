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

    public int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint,
        Guid transactionId, IReadOnlyList<DatabaseInfo> databases, out DatabaseInfo? selectedDatabase)
    {
        selectedDatabase = null;
        return Verify(pRequest, username, displayHint, transactionId);
    }

    public int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId)
        => Verify(pRequest, username, displayHint, transactionId);

    private static unsafe int Verify(nint pRequest, string username, string displayHint, Guid transactionId)
    {
        var ptr = (WebAuthnPluginOperationRequest*)pRequest;
        nint hwnd = ptr->hWnd != 0 ? ptr->hWnd : Win32Native.GetForegroundWindow();
        Log.Info($"hWnd=0x{hwnd:X} username={username} displayHint={displayHint}");

        byte[]? uvKey = SignatureVerifier.GetUserVerificationPublicKey();
        if (uvKey == null)
        {
#if DEBUG
            Log.Warn("UV public key unavailable, skipping UV signature verification");
#else
            Log.Error("UV public key unavailable, rejecting operation");
            return HResults.NTE_BAD_SIGNATURE;
#endif
        }

        fixed (char* usernamePin = username.Length > 0 ? username : "\0")
        fixed (char* hintPin = displayHint.Length > 0 ? displayHint : "\0")
        {
            var uvReq = new WebAuthnPluginUserVerificationRequest
            {
                hwnd               = hwnd,
                rguidTransactionId = &transactionId,
                pwszUsername       = username.Length > 0    ? usernamePin : null,
                pwszDisplayHint    = displayHint.Length > 0 ? hintPin     : null,
            };

            uint cbResp = 0;
            byte* pbResp = null;
            int hr = WebAuthnPluginApi.WebAuthNPluginPerformUserVerification(&uvReq, &cbResp, &pbResp);
            Log.Info($"WebAuthNPluginPerformUserVerification hr=0x{hr:X8}");

            try
            {
                if (hr < HResults.S_OK) return hr;

#if DEBUG
                // uvKey is only null here in Debug (Release rejected above); skip the check.
                if (uvKey == null) return HResults.S_OK;
#endif

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
