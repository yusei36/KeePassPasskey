using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KeePassPasskeyShared
{
    public static class AuthenticatorData
    {
        // Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) | AT(0x40) = 0x5D
        private const byte RegistrationFlags = 0x5D;
        // Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) = 0x1D
        private const byte AuthenticationFlags = 0x1D;

        public static byte[] BuildForRegistration(string rpId, byte[] aaguid, byte[] credentialId, byte[] coseKey)
        {
            using (var ms = new MemoryStream())
            {
                WriteRpIdHash(ms, rpId);
                ms.WriteByte(RegistrationFlags);
                WriteUInt32BE(ms, 0); // sign count = 0
                ms.Write(aaguid, 0, aaguid.Length);
                ms.WriteByte((byte)(credentialId.Length >> 8));
                ms.WriteByte((byte)credentialId.Length);
                ms.Write(credentialId, 0, credentialId.Length);
                ms.Write(coseKey, 0, coseKey.Length);
                return ms.ToArray();
            }
        }

        public static byte[] BuildForAuthentication(string rpId, uint signCount)
        {
            using (var ms = new MemoryStream())
            {
                WriteRpIdHash(ms, rpId);
                ms.WriteByte(AuthenticationFlags);
                WriteUInt32BE(ms, signCount);
                return ms.ToArray();
            }
        }

        private static void WriteRpIdHash(MemoryStream ms, string rpId)
        {
            using (var sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(rpId));
                ms.Write(hash, 0, hash.Length);
            }
        }

        private static void WriteUInt32BE(MemoryStream ms, uint value)
        {
            ms.WriteByte((byte)(value >> 24));
            ms.WriteByte((byte)(value >> 16));
            ms.WriteByte((byte)(value >> 8));
            ms.WriteByte((byte)value);
        }
    }
}
