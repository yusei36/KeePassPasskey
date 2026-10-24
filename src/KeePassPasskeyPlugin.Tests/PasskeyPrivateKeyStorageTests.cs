// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassLib;
using KeePassLib.Security;
using KeePassPasskey.Passkey;
using KeePassPasskey.Storage;
using KeePassPasskeyShared.Passkey;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PasskeyPrivateKeyStorageTests
{
	private const string FieldPrivateKey = "KPEX_PASSKEY_PRIVATE_KEY_PEM";

	// Looking up candidates must not decrypt any key.
	[Fact]
	public void ExtractCredential_KeepsEntryProtectedString()
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(PasskeyAlgorithm.ES256);
		var entry = new PwEntry(true, true);
		entry.Strings.Set(FieldPrivateKey, privateKey);

		var credential = PasskeyEntryStorage.ExtractCredential(entry, null!);

		Assert.Same(privateKey, credential.PrivateKey);
	}

	[Fact]
	public void ExtractCredential_NoKeyField_LeavesKeyNull()
	{
		var credential = PasskeyEntryStorage.ExtractCredential(new PwEntry(true, true), null!);

		Assert.Null(credential.PrivateKey);
	}

	[Fact]
	public void ApplyPasskeyFields_ProtectedKey_IsCopiedWithoutDecrypting()
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(PasskeyAlgorithm.EdDSA);
		var target = new PwEntry(true, true);

		PasskeyEntryStorage.ApplyPasskeyFields(target, NewCredential(privateKey));

		Assert.Same(privateKey, target.Strings.Get(FieldPrivateKey));
	}

	[Fact]
	public void ApplyPasskeyFields_UnprotectedKey_IsProtectedOnTarget()
	{
		var (privateKey, _) = PasskeyKeyHelper.GenerateKeyPair(PasskeyAlgorithm.ES256);
		var unprotected = privateKey.WithProtection(false);
		var target = new PwEntry(true, true);

		PasskeyEntryStorage.ApplyPasskeyFields(target, NewCredential(unprotected));

		var stored = target.Strings.Get(FieldPrivateKey);
		Assert.True(stored.IsProtected);
		Assert.Equal(privateKey.ReadString(), stored.ReadString());
	}

	[Fact]
	public void ApplyPasskeyFields_NoKey_WritesEmptyProtectedField()
	{
		var target = new PwEntry(true, true);

		PasskeyEntryStorage.ApplyPasskeyFields(target, NewCredential(null));

		var stored = target.Strings.Get(FieldPrivateKey);
		Assert.True(stored.IsProtected);
		Assert.True(stored.IsEmpty);
	}

	private static PasskeyCredential NewCredential(ProtectedString? privateKey) => new()
	{
		CredentialId = "Y3JlZA",
		RelyingParty = "example.com",
		PrivateKey = privateKey,
	};
}
