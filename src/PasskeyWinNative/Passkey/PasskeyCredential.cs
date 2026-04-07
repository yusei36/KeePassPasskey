namespace PasskeyWinNative.Passkey
{
    internal sealed class PasskeyCredential
    {
        internal string CredentialId { get; set; }
        internal string PrivateKeyPem { get; set; }
        internal string RelyingParty { get; set; }
        internal string UserHandle { get; set; }
        internal string Username { get; set; }
        internal string RpName { get; set; }
        internal string Origin { get; set; }
    }
}
