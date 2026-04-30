namespace KeePassPasskey.Passkey
{
    internal sealed class PublicKeyComponents
    {
        // ES256 (P-256)
        internal byte[] X { get; set; }
        internal byte[] Y { get; set; }

        // EdDSA (Ed25519)
        internal byte[] EdPublicKey { get; set; }

        // RS256 (RSA-2048)
        internal byte[] N { get; set; }
        internal byte[] E { get; set; }
    }
}
