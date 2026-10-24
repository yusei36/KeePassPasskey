// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using KeePassLib.Security;
using KeePassPasskey.Passkey;
using KeePassPasskeyShared.Passkey;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PasskeyKeyHelperTests
{
	private static readonly byte[] Data = Encoding.ASCII.GetBytes("authenticatorData || clientDataHash");

	// RFC 8410 section 10.3 example key, i.e. one written by another implementation.
	private const string Rfc8410Ed25519Pem =
		"-----BEGIN PRIVATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n" +
		"-----END PRIVATE KEY-----";

	public static TheoryData<PasskeyAlgorithm> Algorithms => new()
	{
		PasskeyAlgorithm.ES256,
		PasskeyAlgorithm.EdDSA,
		PasskeyAlgorithm.RS256,
	};

	// Also proves ProtectedString copies its input, since the export zeroes the buffer it passed in.
	[Theory]
	[MemberData(nameof(Algorithms))]
	public void GenerateKeyPair_SignatureVerifiesWithPublicKey(PasskeyAlgorithm alg)
	{
		var (privateKey, pub) = PasskeyKeyHelper.GenerateKeyPair(alg);

		byte[] signature = PasskeyKeyHelper.Sign(privateKey, Data);

		Assert.True(Verify(alg, pub, Data, signature));
	}

	[Theory]
	[MemberData(nameof(Algorithms))]
	public void GenerateKeyPair_StoresProtectedPkcs8Pem(PasskeyAlgorithm alg)
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(alg);

		Assert.True(privateKey.IsProtected);
		string pem = privateKey.ReadString();
		Assert.StartsWith("-----BEGIN PRIVATE KEY-----\r\n", pem);
		Assert.EndsWith("\r\n-----END PRIVATE KEY-----\r\n", pem);
		Assert.All(pem.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries), line => Assert.True(line.Length <= 64));
	}

	// All three schemes sign deterministically, so equal signatures mean the same key was loaded.
	[Theory]
	[MemberData(nameof(Algorithms))]
	public void Sign_LfLineEndingsWithoutTrailingNewline_LoadsSameKey(PasskeyAlgorithm alg)
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(alg);
		var relaxed = new ProtectedString(true, privateKey.ReadString().Replace("\r\n", "\n").TrimEnd());

		Assert.Equal(PasskeyKeyHelper.Sign(privateKey, Data), PasskeyKeyHelper.Sign(relaxed, Data));
	}

	[Fact]
	public void Sign_ForeignEd25519Pkcs8Key_VerifiesWithDerivedPublicKey()
	{
		var privateKey = new ProtectedString(true, Rfc8410Ed25519Pem);
		var parsed = (Ed25519PrivateKeyParameters)ReadPem(Rfc8410Ed25519Pem);

		byte[] signature = PasskeyKeyHelper.Sign(privateKey, Data);

		var verifier = new Ed25519Signer();
		verifier.Init(false, parsed.GeneratePublicKey());
		verifier.BlockUpdate(Data, 0, Data.Length);
		Assert.True(verifier.VerifySignature(signature));
	}

	[Theory]
	[InlineData(PasskeyAlgorithm.ES256)]
	[InlineData(PasskeyAlgorithm.RS256)]
	public void Sign_NonPkcs8Pem_FallsBackToSameKey(PasskeyAlgorithm alg)
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(alg);
		var key = ReadPem(privateKey.ReadString());
		var sw = new StringWriter();
		new PemWriter(sw).WriteObject(key);
		Assert.DoesNotContain("BEGIN PRIVATE KEY", sw.ToString());

		var legacy = new ProtectedString(true, sw.ToString());

		Assert.Equal(PasskeyKeyHelper.Sign(privateKey, Data), PasskeyKeyHelper.Sign(legacy, Data));
	}

	[Fact]
	public void Sign_NullKey_Throws()
	{
		Assert.Throws<CryptographicException>(() => PasskeyKeyHelper.Sign(null, Data));
	}

	[Fact]
	public void Sign_EmptyKey_Throws()
	{
		Assert.Throws<CryptographicException>(() => PasskeyKeyHelper.Sign(ProtectedString.EmptyEx, Data));
	}

	[Fact]
	public void Sign_NotAKey_Throws()
	{
		Assert.Throws<CryptographicException>(() => PasskeyKeyHelper.Sign(new ProtectedString(true, "not a key"), Data));
	}

	// Pins the layout the former PemWriter-based export produced, so stored keys stay byte-identical.
	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(47)]
	[InlineData(48)]
	[InlineData(49)]
	[InlineData(1217)]
	public void EncodePem_MatchesFormerLayout_AndDecodesBack(int length)
	{
		byte[] der = Enumerable.Range(0, length).Select(i => (byte)(i * 7)).ToArray();

		byte[] pem = PasskeyKeyHelper.EncodePem(der, "PRIVATE KEY");

		var expected = new StringBuilder("-----BEGIN PRIVATE KEY-----\r\n");
		string b64 = Convert.ToBase64String(der);
		for (int i = 0; i < b64.Length; i += 64)
			expected.Append(b64.Substring(i, Math.Min(64, b64.Length - i))).Append("\r\n");
		expected.Append("-----END PRIVATE KEY-----\r\n");
		Assert.Equal(expected.ToString(), Encoding.ASCII.GetString(pem));
		Assert.Equal(der, PasskeyKeyHelper.DecodePem(pem, "PRIVATE KEY"));
	}

	[Theory]
	[InlineData("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")]          // other label
	[InlineData("-----BEGIN PRIVATE KEY-----\nAAAA\n")]                                              // no end line
	[InlineData("-----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END PRIVATE KEY-----")] // headers
	[InlineData("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----")]                       // bad base64 length
	[InlineData("")]
	public void DecodePem_NotPlainPkcs8_ReturnsNull(string pem)
	{
		Assert.Null(PasskeyKeyHelper.DecodePem(Encoding.ASCII.GetBytes(pem), "PRIVATE KEY"));
	}

	private static AsymmetricKeyParameter ReadPem(string pem)
	{
		var obj = new PemReader(new StringReader(pem)).ReadObject();
		return obj is AsymmetricCipherKeyPair pair ? pair.Private : (AsymmetricKeyParameter)obj;
	}

	private static bool Verify(PasskeyAlgorithm alg, PublicKeyComponents pub, byte[] data, byte[] signature)
	{
		ISigner verifier;
		ICipherParameters key;
		switch (alg)
		{
			case PasskeyAlgorithm.ES256:
				var curve = NistNamedCurves.GetByName("P-256");
				var point = curve.Curve.CreatePoint(new BigInteger(1, pub.X), new BigInteger(1, pub.Y));
				key = new ECPublicKeyParameters(point, new ECDomainParameters(curve));
				verifier = new DsaDigestSigner(new ECDsaSigner(), new Sha256Digest());
				break;
			case PasskeyAlgorithm.EdDSA:
				key = new Ed25519PublicKeyParameters(pub.EdPublicKey, 0);
				verifier = new Ed25519Signer();
				break;
			case PasskeyAlgorithm.RS256:
				key = new RsaKeyParameters(false, new BigInteger(1, pub.N), new BigInteger(1, pub.E));
				verifier = new RsaDigestSigner(new Sha256Digest());
				break;
			default:
				throw new ArgumentOutOfRangeException(nameof(alg));
		}
		verifier.Init(false, key);
		verifier.BlockUpdate(data, 0, data.Length);
		return verifier.VerifySignature(signature);
	}
}
