// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>Verifies platform signatures (op-signing, user verification) via CNG.</summary>
internal static unsafe class SignatureVerifier
{
    private const uint BCRYPT_RSAPUBLIC_MAGIC = 0x31415352; // "RSA1" (bcrypt.h)

    private unsafe delegate int PublicKeyGetter(in Guid rclsid, uint* pcb, byte** ppb);

    /// <summary>
    /// Verifies a request signature against the live op-signing key.
    /// </summary>
    public static int VerifyIfKeyAvailable(
        byte* pbData, uint cbData,
        byte* pbSignature, uint cbSignature)
    {
        byte[]? keyBlob = GetOperationSigningPublicKey();
        if (keyBlob == null)
        {
            Log.Error("no key available, rejecting operation");
            return HResults.NTE_BAD_SIGNATURE;
        }

        return VerifySignature(
            new ReadOnlySpan<byte>(pbData, (int)cbData),
            keyBlob,
            new ReadOnlySpan<byte>(pbSignature, (int)cbSignature));
    }

    /// <summary>Verifies a signature over data with a BCrypt key blob; exceptions become HRESULTs.</summary>
    public static int VerifySignature(
        ReadOnlySpan<byte> data,
        byte[] keyBlob,
        ReadOnlySpan<byte> signature)
    {
        try
        {
            return Verify(data, keyBlob, signature);
        }
        catch (Exception ex)
        {
            Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
            return Marshal.GetHRForException(ex);
        }
    }

    private static int Verify(
        ReadOnlySpan<byte> data,
        byte[] keyBlob,
        ReadOnlySpan<byte> signature)
    {
        // RSA vs EC from the key blob magic (first 4 bytes)
        bool isRsa = keyBlob.Length >= 4 &&
                     BitConverter.ToUInt32(keyBlob, 0) == BCRYPT_RSAPUBLIC_MAGIC;

        CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.GenericPublicBlob);
        byte[] hash = SHA256.HashData(data);

        if (isRsa)
        {
            using var rsa = new RSACng(cngKey);
            bool valid = rsa.VerifyHash(hash, signature.ToArray(),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!valid) Log.Warn("RSA signature invalid");
            else        Log.Info("RSA signature valid");
            return valid ? HResults.S_OK : HResults.NTE_BAD_SIGNATURE;
        }
        else
        {
            using var ecdsa = new ECDsaCng(cngKey);
            bool valid = ecdsa.VerifyHash(hash, signature.ToArray());
            if (!valid) Log.Warn("ECDSA signature invalid");
            else        Log.Info("ECDSA signature valid");
            return valid ? HResults.S_OK : HResults.NTE_BAD_SIGNATURE;
        }
    }

    /// <summary>Live op-signing public key for this CLSID; null if unavailable.</summary>
    internal static byte[]? GetOperationSigningPublicKey()
        => FetchPublicKey("op-signing", WebAuthnPluginApi.WebAuthNPluginGetOperationSigningPublicKey);

    /// <summary>UV public key for this CLSID, to verify the PerformUserVerification response; null if unavailable.</summary>
    internal static byte[]? GetUserVerificationPublicKey()
        => FetchPublicKey("user-verification", WebAuthnPluginApi.WebAuthNPluginGetUserVerificationPublicKey);

    private static byte[]? FetchPublicKey(string label, PublicKeyGetter getter)
    {
        Guid clsid = PluginConstants.KeePassPasskeyProviderClsid;
        uint cb = 0;
        byte* pb = null;

        int hr = getter(in clsid, &cb, &pb);
        if (hr < HResults.S_OK || pb == null || cb == 0)
        {
            Log.Error($"{label} public key hr=0x{hr:X8} cb={cb}");
            return null;
        }

        try
        {
            byte[] blob = new ReadOnlySpan<byte>(pb, (int)cb).ToArray();
            Log.Info($"fetched {label} key blob {blob.Length} bytes");
            return blob;
        }
        finally
        {
            WebAuthnPluginApi.WebAuthNPluginFreePublicKeyResponse(pb);
        }
    }
}
