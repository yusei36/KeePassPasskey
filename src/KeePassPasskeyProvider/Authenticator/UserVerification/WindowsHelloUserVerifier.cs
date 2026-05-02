using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal sealed class WindowsHelloUserVerifier : IUserVerifier
{
    public UserVerificationMode Mode => UserVerificationMode.WindowsHello;

    public int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint, Guid transactionId)
        => Verify(pRequest, username, displayHint, transactionId);

    public int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId)
        => Verify(pRequest, username, displayHint, transactionId);

    private static unsafe int Verify(nint pRequest, string username, string displayHint, Guid transactionId)
    {
        var ptr = (WebAuthnPluginOperationRequest*)pRequest;
        nint hwnd = ptr->hWnd != 0 ? ptr->hWnd : Win32Native.GetForegroundWindow();
        Log.Info($"hWnd=0x{hwnd:X} username={username} displayHint={displayHint}");

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
}
