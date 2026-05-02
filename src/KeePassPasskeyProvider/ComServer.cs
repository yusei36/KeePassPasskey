using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyProvider.Authenticator.Native;

namespace KeePassPasskeyProvider;

internal static class ComServer
{
    internal static uint Register(ClassFactory factory)
        => ComRegistration.RegisterClassFactory(factory);

    internal static void Revoke(uint cookie)
        => ComRegistration.RevokeClassFactory(cookie);
}
