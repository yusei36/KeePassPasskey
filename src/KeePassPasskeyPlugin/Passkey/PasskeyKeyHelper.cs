using System;
using System.IO;
using System.Security.Cryptography;
using KeePassPasskeyShared.Passkey;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using PeterO.Cbor;

namespace KeePassPasskey.Passkey
{
    internal static class PasskeyKeyHelper
    {
        private static readonly SecureRandom Rng = new SecureRandom();

        // secp256r1 / prime256v1 OID — used to produce named-curve PKCS#8 matching Botan/KeePassXC
        private static readonly DerObjectIdentifier P256Oid = new DerObjectIdentifier("1.2.840.10045.3.1.7");

        internal static (string privateKeyPem, PublicKeyComponents pub) GenerateKeyPair(PasskeyAlgorithm alg)
        {
            AsymmetricCipherKeyPair keyPair;
            PublicKeyComponents pub;

            switch (alg)
            {
                case PasskeyAlgorithm.ES256:
                {
                    var curve = NistNamedCurves.GetByName("P-256");
                    // ECNamedDomainParameters carries the OID so PrivateKeyInfoFactory writes
                    // PKCS#8 with a named curve AlgorithmIdentifier, matching Botan/KeePassXC format.
                    var domainParams = new ECNamedDomainParameters(P256Oid, curve);
                    var gen = new ECKeyPairGenerator();
                    gen.Init(new ECKeyGenerationParameters(domainParams, Rng));
                    keyPair = gen.GenerateKeyPair();
                    var ecPub = (ECPublicKeyParameters)keyPair.Public;
                    var q = ecPub.Q.Normalize();
                    pub = new PublicKeyComponents
                    {
                        X = BigIntegers.AsUnsignedByteArray(32, q.AffineXCoord.ToBigInteger()),
                        Y = BigIntegers.AsUnsignedByteArray(32, q.AffineYCoord.ToBigInteger()),
                    };
                    break;
                }
                case PasskeyAlgorithm.EdDSA:
                {
                    var gen = new Ed25519KeyPairGenerator();
                    gen.Init(new Ed25519KeyGenerationParameters(Rng));
                    keyPair = gen.GenerateKeyPair();
                    var edPub = (Ed25519PublicKeyParameters)keyPair.Public;
                    pub = new PublicKeyComponents { EdPublicKey = edPub.GetEncoded() };
                    break;
                }
                case PasskeyAlgorithm.RS256:
                {
                    var gen = new RsaKeyPairGenerator();
                    gen.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), Rng, 2048, 80));
                    keyPair = gen.GenerateKeyPair();
                    var rsaPub = (RsaKeyParameters)keyPair.Public;
                    pub = new PublicKeyComponents
                    {
                        N = rsaPub.Modulus.ToByteArrayUnsigned(),
                        E = rsaPub.Exponent.ToByteArrayUnsigned(),
                    };
                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(alg), alg, null);
            }

            return (ExportPrivateKeyPem(keyPair.Private), pub);
        }

        internal static byte[] BuildCoseKey(PasskeyAlgorithm alg, PublicKeyComponents pub)
        {
            var options = new CBOREncodeOptions("ctap2canonical=true");
            var map = CBORObject.NewMap();

            switch (alg)
            {
                case PasskeyAlgorithm.ES256:
                    map.Add(1, 2);          // kty: EC2
                    map.Add(3, -7);         // alg: ES256
                    map.Add(-1, 1);         // crv: P-256
                    map.Add(-2, pub.X);     // x coordinate
                    map.Add(-3, pub.Y);     // y coordinate
                    break;
                case PasskeyAlgorithm.EdDSA:
                    map.Add(1, 1);                  // kty: OKP
                    map.Add(3, -8);                 // alg: EdDSA
                    map.Add(-1, 6);                 // crv: Ed25519
                    map.Add(-2, pub.EdPublicKey);   // public key
                    break;
                case PasskeyAlgorithm.RS256:
                    map.Add(1, 3);      // kty: RSA
                    map.Add(3, -257);   // alg: RS256
                    map.Add(-1, pub.N); // modulus
                    map.Add(-2, pub.E); // exponent
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(alg), alg, null);
            }

            return map.EncodeToBytes(options);
        }

        internal static PasskeyAlgorithm DetectAlgorithm(string pem)
        {
            var key = LoadPrivateKey(pem);
            return key switch
            {
                ECPrivateKeyParameters _ => PasskeyAlgorithm.ES256,
                Ed25519PrivateKeyParameters _ => PasskeyAlgorithm.EdDSA,
                RsaPrivateCrtKeyParameters _ => PasskeyAlgorithm.RS256,
                _ => throw new CryptographicException($"Unsupported private key type: {key.GetType().Name}")
            };
        }

        internal static byte[] Sign(string pem, byte[] dataToSign)
        {
            var key = LoadPrivateKey(pem);

            switch (key)
            {
                case ECPrivateKeyParameters ecKey:
                {
                    // RFC 6979 deterministic ECDSA with SHA-256, DER output
                    var signer = new DsaDigestSigner(
                        new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest())),
                        new Sha256Digest());
                    signer.Init(true, ecKey);
                    signer.BlockUpdate(dataToSign, 0, dataToSign.Length);
                    return signer.GenerateSignature();
                }
                case Ed25519PrivateKeyParameters edKey:
                {
                    var signer = new Ed25519Signer();
                    signer.Init(true, edKey);
                    signer.BlockUpdate(dataToSign, 0, dataToSign.Length);
                    return signer.GenerateSignature();
                }
                case RsaPrivateCrtKeyParameters rsaKey:
                {
                    var signer = new RsaDigestSigner(new Sha256Digest());
                    signer.Init(true, rsaKey);
                    signer.BlockUpdate(dataToSign, 0, dataToSign.Length);
                    return signer.GenerateSignature();
                }
                default:
                    throw new CryptographicException($"Unsupported private key type: {key.GetType().Name}");
            }
        }

        private static AsymmetricKeyParameter LoadPrivateKey(string pem)
        {
            using var sr = new StringReader(pem);
            var obj = new PemReader(sr).ReadObject();
            return obj is AsymmetricCipherKeyPair pair ? pair.Private : (AsymmetricKeyParameter)obj;
        }

        private static string ExportPrivateKeyPem(AsymmetricKeyParameter privateKey)
        {
            var sw = new StringWriter();

            if (privateKey is Ed25519PrivateKeyParameters edKey)
            {
                // PrivateKeyInfoFactory.CreatePrivateKeyInfo(Ed25519PrivateKeyParameters) produces PKCS#8 v1
                // with [1] public key — KeePassXC/Botan only accept v0 without the embedded public key.
                var pki = new Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    new DerOctetString(edKey.GetEncoded()));
                new PemWriter(sw).WriteObject(pki);
            }
            else if (privateKey is RsaPrivateCrtKeyParameters rsaKey)
            {
                // PemWriter.WriteObject(RsaPrivateCrtKeyParameters) produces "BEGIN RSA PRIVATE KEY"
                // (PKCS#1 format) — KeePassXC/Botan only accept "BEGIN PRIVATE KEY" (PKCS#8).
                var rsaStruct = new Org.BouncyCastle.Asn1.Pkcs.RsaPrivateKeyStructure(
                    rsaKey.Modulus, rsaKey.PublicExponent, rsaKey.Exponent,
                    rsaKey.P, rsaKey.Q, rsaKey.DP, rsaKey.DQ, rsaKey.QInv);
                var algId = new AlgorithmIdentifier(
                    Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption,
                    DerNull.Instance);
                var pki = new Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo(algId, rsaStruct.ToAsn1Object());
                WritePem(sw, "PRIVATE KEY", pki.GetEncoded());
            }
            else if (privateKey is ECPrivateKeyParameters ecKey)
            {
                // PemWriter.WriteObject(ECPrivateKeyParameters) produces "BEGIN EC PRIVATE KEY"
                // (SEC1 format) — KeePassXC/Botan only accept "BEGIN PRIVATE KEY" (PKCS#8).
                var q = ecKey.Parameters.G.Multiply(ecKey.D).Normalize();
                var ecStruct = new ECPrivateKeyStructure(
                    ecKey.Parameters.N.BitLength,
                    ecKey.D,
                    new DerBitString(q.GetEncoded(false)), // uncompressed public key [1]
                    null);                                  // no [0] — curve OID is in AlgorithmIdentifier
                var algId = new AlgorithmIdentifier(
                    X9ObjectIdentifiers.IdECPublicKey,
                    P256Oid);
                var pki = new Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo(algId, ecStruct.ToAsn1Object());
                WritePem(sw, "PRIVATE KEY", pki.GetEncoded());
            }
            else
            {
                new PemWriter(sw).WriteObject(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));
            }

            return sw.ToString();
        }

        private static void WritePem(StringWriter sw, string type, byte[] der)
        {
            sw.WriteLine($"-----BEGIN {type}-----");
            var b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64)
                sw.WriteLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
            sw.WriteLine($"-----END {type}-----");
        }
    }
}
