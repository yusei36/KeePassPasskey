// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Security;
using KeePassLib.Utility;
using KeePassPasskeyShared.Passkey;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
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

namespace KeePassPasskey.Passkey;

internal static class PasskeyKeyHelper
{
	private static readonly SecureRandom Rng = new SecureRandom();

	// secp256r1 / prime256v1 OID - used to produce named-curve PKCS#8 matching Botan/KeePassXC
	private static readonly DerObjectIdentifier P256Oid = new DerObjectIdentifier("1.2.840.10045.3.1.7");

	private const string Pkcs8Label = "PRIVATE KEY";

	internal static (ProtectedString privateKey, PublicKeyComponents pub) GenerateKeyPair(PasskeyAlgorithm alg)
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

		return (ExportPrivateKey(keyPair.Private), pub);
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

	internal static byte[] Sign(ProtectedString privateKey, byte[] dataToSign)
	{
		var key = LoadPrivateKey(privateKey);

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

	// The plaintext key only ever lives in byte/char arrays that are zeroed after use, never in a string.
	private static AsymmetricKeyParameter LoadPrivateKey(ProtectedString privateKey)
	{
		if (privateKey == null || privateKey.IsEmpty)
			throw new CryptographicException("The entry holds no passkey private key");

		byte[] pem = privateKey.ReadUtf8();
		try
		{
			byte[] der = DecodePem(pem, Pkcs8Label);
			if (der == null)
				return LoadPrivateKeyFromOtherPem(pem);
			try { return PrivateKeyFactory.CreateKey(der); }
			finally { MemUtil.ZeroByteArray(der); }
		}
		finally { MemUtil.ZeroByteArray(pem); }
	}

	// Only for non-PKCS#8 PEM (e.g. SEC1, PKCS#1): PemReader needs the key as a string.
	private static AsymmetricKeyParameter LoadPrivateKeyFromOtherPem(byte[] pem)
	{
		using var sr = new StringReader(Encoding.UTF8.GetString(pem));
		var obj = new PemReader(sr).ReadObject();
		var key = obj is AsymmetricCipherKeyPair pair ? pair.Private : obj as AsymmetricKeyParameter;
		return key ?? throw new CryptographicException("The passkey private key is not a supported PEM key");
	}

	// Null when there is no such block or it carries headers (an encrypted key), so the caller falls back.
	internal static byte[] DecodePem(byte[] pem, string label)
	{
		byte[] begin = Encoding.ASCII.GetBytes("-----BEGIN " + label + "-----");
		byte[] end = Encoding.ASCII.GetBytes("-----END " + label + "-----");
		int bodyStart = IndexOf(pem, begin, 0);
		if (bodyStart < 0) return null;
		bodyStart += begin.Length;
		int bodyEnd = IndexOf(pem, end, bodyStart);
		if (bodyEnd < 0) return null;

		char[] base64 = new char[bodyEnd - bodyStart];
		int count = 0;
		try
		{
			for (int i = bodyStart; i < bodyEnd; i++)
			{
				char c = (char)pem[i];
				if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
				if (!IsBase64Char(c)) return null;
				base64[count++] = c;
			}
			return Convert.FromBase64CharArray(base64, 0, count);
		}
		catch (FormatException) { return null; }
		finally { MemUtil.ZeroArray(base64); }
	}

	private static bool IsBase64Char(char c)
		=> (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';

	private static int IndexOf(byte[] haystack, byte[] needle, int start)
	{
		for (int i = start; i <= haystack.Length - needle.Length; i++)
		{
			int j = 0;
			while (j < needle.Length && haystack[i + j] == needle[j]) j++;
			if (j == needle.Length) return i;
		}
		return -1;
	}

	private static ProtectedString ExportPrivateKey(AsymmetricKeyParameter privateKey)
	{
		byte[] der = BuildPrivateKeyInfo(privateKey).GetEncoded();
		byte[] pem = null;
		try
		{
			pem = EncodePem(der, Pkcs8Label);
			return new ProtectedString(true, pem);
		}
		finally
		{
			MemUtil.ZeroByteArray(der);
			if (pem != null) MemUtil.ZeroByteArray(pem);
		}
	}

	// Always PKCS#8 ("BEGIN PRIVATE KEY"): KeePassXC/Botan accept nothing else.
	private static PrivateKeyInfo BuildPrivateKeyInfo(AsymmetricKeyParameter privateKey)
	{
		if (privateKey is Ed25519PrivateKeyParameters edKey)
		{
			// PrivateKeyInfoFactory.CreatePrivateKeyInfo(Ed25519PrivateKeyParameters) produces PKCS#8 v1
			// with [1] public key - KeePassXC/Botan only accept v0 without the embedded public key.
			return new PrivateKeyInfo(
				new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
				new DerOctetString(edKey.GetEncoded()));
		}
		if (privateKey is RsaPrivateCrtKeyParameters rsaKey)
		{
			var rsaStruct = new RsaPrivateKeyStructure(
				rsaKey.Modulus, rsaKey.PublicExponent, rsaKey.Exponent,
				rsaKey.P, rsaKey.Q, rsaKey.DP, rsaKey.DQ, rsaKey.QInv);
			var algId = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
			return new PrivateKeyInfo(algId, rsaStruct.ToAsn1Object());
		}
		if (privateKey is ECPrivateKeyParameters ecKey)
		{
			var q = ecKey.Parameters.G.Multiply(ecKey.D).Normalize();
			var ecStruct = new ECPrivateKeyStructure(
				ecKey.Parameters.N.BitLength,
				ecKey.D,
				new DerBitString(q.GetEncoded(false)), // uncompressed public key [1]
				null);                                  // no [0] - curve OID is in AlgorithmIdentifier
			var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, P256Oid);
			return new PrivateKeyInfo(algId, ecStruct.ToAsn1Object());
		}
		return PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
	}

	// One exactly sized buffer, so a growing buffer leaves no partial copies of the key behind.
	internal static byte[] EncodePem(byte[] der, string label)
	{
		const string NewLine = "\r\n";
		string header = "-----BEGIN " + label + "-----" + NewLine;
		string footer = "-----END " + label + "-----" + NewLine;

		char[] base64 = new char[(der.Length + 2) / 3 * 4];
		try
		{
			Convert.ToBase64CharArray(der, 0, der.Length, base64, 0);
			int lineCount = (base64.Length + 63) / 64;
			var pem = new byte[header.Length + base64.Length + lineCount * NewLine.Length + footer.Length];

			int pos = Encoding.ASCII.GetBytes(header, 0, header.Length, pem, 0);
			for (int i = 0; i < base64.Length; i += 64)
			{
				int len = Math.Min(64, base64.Length - i);
				for (int j = 0; j < len; j++)
					pem[pos++] = (byte)base64[i + j];
				pem[pos++] = (byte)'\r';
				pem[pos++] = (byte)'\n';
			}
			Encoding.ASCII.GetBytes(footer, 0, footer.Length, pem, pos);
			return pem;
		}
		finally { MemUtil.ZeroArray(base64); }
	}
}
