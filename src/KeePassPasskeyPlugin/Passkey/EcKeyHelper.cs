using System;
using System.IO;
using System.Security.Cryptography;

namespace KeePassPasskey.Passkey
{
    internal static class EcKeyHelper
    {
        // OID 1.2.840.10045.2.1 (ecPublicKey)
        private static readonly byte[] EcPublicKeyOid = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
        // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
        private static readonly byte[] P256Oid = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

        internal static void GenerateKeyPair(out byte[] x, out byte[] y, out byte[] d)
        {
            using (var ecdsa = new ECDsaCng(256))
            {
                ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                // EccPrivateBlob: BCRYPT_ECCKEY_BLOB header (8 bytes) + x(32) + y(32) + d(32)
                var blob = ecdsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                var keyLen = BitConverter.ToInt32(blob, 4);
                x = new byte[keyLen];
                y = new byte[keyLen];
                d = new byte[keyLen];
                Array.Copy(blob, 8, x, 0, keyLen);
                Array.Copy(blob, 8 + keyLen, y, 0, keyLen);
                Array.Copy(blob, 8 + 2 * keyLen, d, 0, keyLen);
            }
        }

        internal static string ExportPrivateKeyPem(byte[] d, byte[] x, byte[] y)
        {
            var ecPrivateKey = BuildEcPrivateKey(d, x, y);
            var pkcs8 = BuildPkcs8(ecPrivateKey);
            return "-----BEGIN PRIVATE KEY-----\n"
                + Convert.ToBase64String(pkcs8, Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END PRIVATE KEY-----";
        }

        internal static byte[] ExportPublicKeySpki(byte[] x, byte[] y)
        {
            var uncompressedPoint = new byte[65];
            uncompressedPoint[0] = 0x04;
            Array.Copy(x, 0, uncompressedPoint, 1, 32);
            Array.Copy(y, 0, uncompressedPoint, 33, 32);

            var bitString = WrapBitString(uncompressedPoint);
            var algId = WrapSequence(Concat(EcPublicKeyOid, P256Oid));
            return WrapSequence(Concat(algId, bitString));
        }

        internal static byte[] Sign(string privateKeyPem, byte[] data)
        {
            byte[] d, x, y;
            ImportFromPem(privateKeyPem, out d, out x, out y);

            // Build CNG EccPrivateBlob: magic(4) + keyLength(4) + x(32) + y(32) + d(32)
            var blob = new byte[8 + 32 * 3];
            // BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345
            blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x53; blob[3] = 0x32;
            blob[4] = 32; blob[5] = 0; blob[6] = 0; blob[7] = 0;
            Array.Copy(x, 0, blob, 8, 32);
            Array.Copy(y, 0, blob, 40, 32);
            Array.Copy(d, 0, blob, 72, 32);

            var key = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob);
            using (var ecdsa = new ECDsaCng(key))
            {
                ecdsa.HashAlgorithm = CngAlgorithm.Sha256;
                var p1363Sig = ecdsa.SignData(data);
                return ConvertP1363ToDer(p1363Sig);
            }
        }

        private static void ImportFromPem(string pem, out byte[] d, out byte[] x, out byte[] y)
        {
            var base64 = pem
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "")
                .Replace("\r", "").Replace("\n", "").Trim();
            var der = Convert.FromBase64String(base64);
            ParsePkcs8(der, out d, out x, out y);
        }

        private static void ParsePkcs8(byte[] der, out byte[] d, out byte[] x, out byte[] y)
        {
            int offset = 0;
            ReadTag(der, ref offset, 0x30);
            ReadLength(der, ref offset);

            ReadTag(der, ref offset, 0x02);
            var vLen = ReadLength(der, ref offset);
            offset += vLen;

            ReadTag(der, ref offset, 0x30);
            var algLen = ReadLength(der, ref offset);
            offset += algLen;

            ReadTag(der, ref offset, 0x04);
            ReadLength(der, ref offset);

            ParseEcPrivateKey(der, offset, out d, out x, out y);
        }

        private static void ParseEcPrivateKey(byte[] der, int start, out byte[] d, out byte[] x, out byte[] y)
        {
            int offset = start;
            ReadTag(der, ref offset, 0x30);
            var seqLen = ReadLength(der, ref offset);
            var seqEnd = offset + seqLen;

            ReadTag(der, ref offset, 0x02);
            var vLen = ReadLength(der, ref offset);
            offset += vLen;

            ReadTag(der, ref offset, 0x04);
            var dLen = ReadLength(der, ref offset);
            d = new byte[dLen];
            Array.Copy(der, offset, d, 0, dLen);
            offset += dLen;

            x = null;
            y = null;

            while (offset < seqEnd)
            {
                var tag = der[offset];
                offset++;
                var len = ReadLength(der, ref offset);

                if (tag == 0xA1) // [1] public key
                {
                    ReadTag(der, ref offset, 0x03);
                    var bsLen = ReadLength(der, ref offset);
                    offset++; // skip unused bits byte (0x00)
                    offset++; // skip 0x04 uncompressed point indicator
                    var coordLen = (bsLen - 2) / 2;
                    x = new byte[coordLen];
                    y = new byte[coordLen];
                    Array.Copy(der, offset, x, 0, coordLen);
                    Array.Copy(der, offset + coordLen, y, 0, coordLen);
                    offset += coordLen * 2;
                }
                else
                {
                    offset += len;
                }
            }

            if (x == null || y == null)
            {
                throw new CryptographicException("Cannot regenerate public key from private key alone. PEM must contain the public key.");
            }
        }

        internal static byte[] ConvertP1363ToDer(byte[] p1363)
        {
            var half = p1363.Length / 2;
            var r = TrimLeadingZeros(p1363, 0, half);
            var s = TrimLeadingZeros(p1363, half, half);

            var rNeedsPad = r[0] >= 0x80;
            var sNeedsPad = s[0] >= 0x80;

            var rEncLen = r.Length + (rNeedsPad ? 1 : 0);
            var sEncLen = s.Length + (sNeedsPad ? 1 : 0);

            var totalInner = 2 + rEncLen + 2 + sEncLen;
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x30);
                WriteAsn1Length(ms, totalInner);
                ms.WriteByte(0x02);
                WriteAsn1Length(ms, rEncLen);
                if (rNeedsPad) ms.WriteByte(0x00);
                ms.Write(r, 0, r.Length);
                ms.WriteByte(0x02);
                WriteAsn1Length(ms, sEncLen);
                if (sNeedsPad) ms.WriteByte(0x00);
                ms.Write(s, 0, s.Length);
                return ms.ToArray();
            }
        }

        private static byte[] TrimLeadingZeros(byte[] data, int offset, int length)
        {
            var start = offset;
            var end = offset + length;
            while (start < end - 1 && data[start] == 0)
                start++;
            var result = new byte[end - start];
            Array.Copy(data, start, result, 0, result.Length);
            return result;
        }

        private static byte[] BuildEcPrivateKey(byte[] d, byte[] x, byte[] y)
        {
            var uncompressedPoint = new byte[65];
            uncompressedPoint[0] = 0x04;
            Array.Copy(x, 0, uncompressedPoint, 1, 32);
            Array.Copy(y, 0, uncompressedPoint, 33, 32);

            var version = new byte[] { 0x02, 0x01, 0x01 };
            var privKey = WrapOctetString(d);
            var curveParam = WrapExplicit(0, P256Oid);
            var pubKey = WrapExplicit(1, WrapBitString(uncompressedPoint));

            return WrapSequence(Concat(Concat(version, privKey), Concat(curveParam, pubKey)));
        }

        private static byte[] BuildPkcs8(byte[] ecPrivateKey)
        {
            var version = new byte[] { 0x02, 0x01, 0x00 };
            var algId = WrapSequence(Concat(EcPublicKeyOid, P256Oid));
            var privKey = WrapOctetString(ecPrivateKey);
            return WrapSequence(Concat(Concat(version, algId), privKey));
        }

        private static byte[] WrapSequence(byte[] content) => WrapTag(0x30, content);
        private static byte[] WrapOctetString(byte[] content) => WrapTag(0x04, content);

        private static byte[] WrapBitString(byte[] content)
        {
            var inner = new byte[content.Length + 1];
            inner[0] = 0x00;
            Array.Copy(content, 0, inner, 1, content.Length);
            return WrapTag(0x03, inner);
        }

        private static byte[] WrapExplicit(int tagNum, byte[] content) => WrapTag((byte)(0xA0 | tagNum), content);

        private static byte[] WrapTag(byte tag, byte[] content)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(tag);
                WriteAsn1Length(ms, content.Length);
                ms.Write(content, 0, content.Length);
                return ms.ToArray();
            }
        }

        private static void WriteAsn1Length(MemoryStream ms, int length)
        {
            if (length < 0x80)
                ms.WriteByte((byte)length);
            else if (length <= 0xFF)
            {
                ms.WriteByte(0x81);
                ms.WriteByte((byte)length);
            }
            else
            {
                ms.WriteByte(0x82);
                ms.WriteByte((byte)(length >> 8));
                ms.WriteByte((byte)length);
            }
        }

        private static void ReadTag(byte[] der, ref int offset, byte expectedTag)
        {
            if (der[offset] != expectedTag)
                throw new CryptographicException(
                    string.Format("Expected ASN.1 tag 0x{0:X2} but got 0x{1:X2} at offset {2}",
                        expectedTag, der[offset], offset));
            offset++;
        }

        private static int ReadLength(byte[] der, ref int offset)
        {
            var b = der[offset++];
            if (b < 0x80) return b;
            var numBytes = b & 0x7F;
            var length = 0;
            for (var i = 0; i < numBytes; i++)
                length = (length << 8) | der[offset++];
            return length;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
