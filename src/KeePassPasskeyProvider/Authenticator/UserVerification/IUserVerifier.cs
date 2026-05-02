using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal interface IUserVerifier
{
    UserVerificationMode Mode { get; }
    int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint, Guid transactionId);
    int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId);
}
