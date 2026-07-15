// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KeePassPasskeyShared;

public static class AuthenticatorData
{
	private const byte FlagUp = 0x01; // User Present
	private const byte FlagUv = 0x04; // User Verified
	private const byte FlagBe = 0x08; // Backup Eligible
	private const byte FlagBs = 0x10; // Backup State
	private const byte FlagAt = 0x40; // Attested credential data

	// BS implies BE: mask BS by BE so an illegal combination is never emitted.
	private static byte BackupFlags(bool backupEligible, bool backupState)
	{
		byte flags = 0;
		if (backupEligible) flags |= FlagBe;
		if (backupState && backupEligible) flags |= FlagBs;
		return flags;
	}

	public static byte[] BuildForRegistration(string rpId, byte[] aaguid, byte[] credentialId, byte[] coseKey, bool backupEligible, bool backupState)
	{
		byte flags = (byte)(FlagUp | FlagUv | FlagAt | BackupFlags(backupEligible, backupState));
		using (var ms = new MemoryStream())
		{
			WriteRpIdHash(ms, rpId);
			ms.WriteByte(flags);
			WriteUInt32BE(ms, 0); // sign count = 0
			ms.Write(aaguid, 0, aaguid.Length);
			ms.WriteByte((byte)(credentialId.Length >> 8));
			ms.WriteByte((byte)credentialId.Length);
			ms.Write(credentialId, 0, credentialId.Length);
			ms.Write(coseKey, 0, coseKey.Length);
			return ms.ToArray();
		}
	}

	public static byte[] BuildForAuthentication(string rpId, uint signCount, bool backupEligible, bool backupState)
	{
		byte flags = (byte)(FlagUp | FlagUv | BackupFlags(backupEligible, backupState));
		using (var ms = new MemoryStream())
		{
			WriteRpIdHash(ms, rpId);
			ms.WriteByte(flags);
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
