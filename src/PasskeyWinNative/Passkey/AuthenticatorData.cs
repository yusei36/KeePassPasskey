using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PasskeyWinNative.Passkey
{
    internal static class AuthenticatorData
    {
        // KeePassXC-compatible AAGUID: fdb141b2-5d84-443e-8a35-4698c205a502
        private static readonly byte[] Aaguid = {
            0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e,
            0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02
        };

        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        // Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) | AT(0x40) = 0x5D
        private const byte RegistrationFlags = 0x5D;
        // Flags: UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) = 0x1D
        private const byte AuthenticationFlags = 0x1D;

        internal static byte[] BuildForRegistration(string rpId, byte[] credentialId, byte[] ecX, byte[] ecY, uint signCount)
        {
            var coseKey = BuildCoseEs256Key(ecX, ecY);

            using (var ms = new MemoryStream())
            {
                WriteRpIdHash(ms, rpId);
                ms.WriteByte(RegistrationFlags);
                WriteUInt32BE(ms, signCount);
                ms.Write(Aaguid, 0, Aaguid.Length);
                ms.WriteByte((byte)(credentialId.Length >> 8));
                ms.WriteByte((byte)(credentialId.Length));
                ms.Write(credentialId, 0, credentialId.Length);
                ms.Write(coseKey, 0, coseKey.Length);
                return ms.ToArray();
            }
        }

        internal static byte[] BuildForAuthentication(string rpId, uint signCount)
        {
            using (var ms = new MemoryStream())
            {
                WriteRpIdHash(ms, rpId);
                ms.WriteByte(AuthenticationFlags);
                WriteUInt32BE(ms, signCount);
                return ms.ToArray();
            }
        }

        private static byte[] BuildCoseEs256Key(byte[] x, byte[] y)
        {
            // COSE Key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
            var cbor = new CborWriter();
            cbor.WriteMapStart(5);
            cbor.WriteUnsignedInt(1);
            cbor.WriteUnsignedInt(2);
            cbor.WriteUnsignedInt(3);
            cbor.WriteNegativeInt(-7);
            cbor.WriteNegativeInt(-1);
            cbor.WriteUnsignedInt(1);
            cbor.WriteNegativeInt(-2);
            cbor.WriteByteString(x);
            cbor.WriteNegativeInt(-3);
            cbor.WriteByteString(y);
            return cbor.ToArray();
        }

        private static void WriteRpIdHash(MemoryStream ms, string rpId)
        {
            using (var sha = new SHA256CryptoServiceProvider())
            {
                var hash = sha.ComputeHash(Utf8.GetBytes(rpId));
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
