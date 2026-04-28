using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;
using KeePassPasskeyProvider.Interop;
using KeePassPasskey.Shared;

namespace KeePassPasskeyProvider.Plugin;

/// <summary>
/// Verifies the platform-supplied operation signing signature.
/// Performs BCrypt key blob import, SHA-256 hash,
/// and RSA/ECDSA verify using managed CNG wrappers.
/// </summary>
internal static unsafe class SignatureVerifier
{
    // BCrypt key blob magic values (from bcrypt.h)
    private const uint BCRYPT_RSAPUBLIC_MAGIC = 0x31415352; // "RSA1"

    /// <summary>
    /// Loads the signing key from the registry and verifies the signature.
    /// Returns S_OK if no key is stored (first run, nothing to verify).
    /// </summary>
    public static int VerifyIfKeyAvailable(
        byte* pbData, uint cbData,
        byte* pbSignature, uint cbSignature)
    {
        byte[]? keyBlob = LoadSigningPublicKey();
        if (keyBlob == null)
        {
#if DEBUG
            Log.Warn("no key stored, skipping verification");
            return HResults.S_OK;
#else
            Log.Error("no key stored, rejecting operation");
            return HResults.NTE_BAD_SIGNATURE;
#endif
        }

        try
        {
            return Verify(
                new ReadOnlySpan<byte>(pbData, (int)cbData),
                keyBlob,
                new ReadOnlySpan<byte>(pbSignature, (int)cbSignature));
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
        // Detect RSA vs EC from the BCrypt key blob magic (first 4 bytes of BCRYPT_KEY_BLOB)
        bool isRsa = keyBlob.Length >= 4 &&
                     BitConverter.ToUInt32(keyBlob, 0) == BCRYPT_RSAPUBLIC_MAGIC;

        // Import the key via CNG (managed wrappers)
        CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.GenericPublicBlob);

        // Hash the data with SHA-256
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

    internal static byte[]? LoadSigningPublicKey()
    {
        try
        {
            using RegistryKey? hkcu = Registry.CurrentUser;
            using RegistryKey? key = hkcu?.OpenSubKey(PluginConstants.PluginRegPath, writable: false);
            if (key == null) return null;

            object? val = key.GetValue(PluginConstants.RegKeySigningKey);
            if (val is byte[] blob && blob.Length > 0)
            {
                Log.Info($"loaded key blob {blob.Length} bytes");
                return blob;
            }
            return null;
        }
        catch (Exception ex)
        {
            Log.Error($"LoadSigningPublicKey failed: {ex.Message}");
            return null;
        }
    }
}
