using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Plugin;

internal static class UserVerification
{
    private static readonly IUserVerifier[] _verifiers =
    [
        new NotificationUserVerifier(),
        new WindowsHelloUserVerifier(),
    ];

    public static int VerifyForRegistration(
        nint pRequest, Guid transactionId,
        string rpId, string rpName, string uvUsername, string uvDisplayHint)
        => Dispatch(AppSettings.Current.RegistrationVerification,
            v => v.VerifyForRegistration(pRequest, rpId, rpName, uvUsername, uvDisplayHint, transactionId));

    public static int VerifyForSignIn(
        nint pRequest, Guid transactionId,
        string rpId, string uvUsername, string uvDisplayHint)
        => Dispatch(AppSettings.Current.SignInVerification,
            v => v.VerifyForSignIn(pRequest, rpId, uvUsername, uvDisplayHint, transactionId));

    private static int Dispatch(UserVerificationMode mode, Func<IUserVerifier, int> call)
    {
        foreach (var verifier in _verifiers)
        {
            if (!mode.HasFlag(verifier.Mode)) continue;
            int hr = call(verifier);
            if (hr < 0) return hr;
        }
        return HResults.S_OK;
    }
}
