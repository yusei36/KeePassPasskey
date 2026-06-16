// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
//
// TEMP PRF OUTPUT-CHANNEL PROBE (remove before merge).
// Confirms the PRF wiring end to end without committing the real storage/IPC design:
//   - parses the WebAuthn `prf` extension out of the raw CBOR extensions map
//     (pbCborExtensionsMap), which is where Windows actually delivers it;
//   - builds the cleartext `prf` extension-output CBOR we hand back to Windows via
//     pbUnsignedExtensionOutputs.
// The assertion HMAC uses a FIXED probe key (not a stored per-credential CredRandom), so the
// output is meaningless cryptographically — this only verifies the plumbing and CBOR format.
// See docs/prf-implementation-plan.md.
using System.Security.Cryptography;
using PeterO.Cbor;

namespace KeePassPasskeyProvider.Authenticator;

internal static class PrfProbe
{
    // Fixed probe key standing in for the per-credential CredRandom (32 bytes).
    private static readonly byte[] FixedProbeKey =
    {
        0xC0, 0xFF, 0xEE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    };

    /// <summary>True when the extensions map contains a `prf` key (PRF requested at registration).</summary>
    internal static bool ExtensionsMapRequestsPrf(byte[]? extensionsMap)
    {
        if (extensionsMap == null || extensionsMap.Length == 0) return false;
        try
        {
            var map = CBORObject.DecodeFromBytes(extensionsMap);
            return map.Type == CBORType.Map && map.ContainsKey("prf");
        }
        catch { return false; }
    }

    /// <summary>Registration extension output: <c>{"prf": {"enabled": true}}</c>.</summary>
    internal static byte[] BuildRegistrationEnabledOutput()
    {
        var outMap = CBORObject.NewMap()
            .Add("prf", CBORObject.NewMap().Add("enabled", true));
        return outMap.EncodeToBytes();
    }

    /// <summary>
    /// Returns a copy of the registration authenticatorData with the ED (extension data) flag set
    /// and a <c>{"hmac-secret": true}</c> CBOR extensions map appended — the CTAP-canonical signal
    /// that hmac-secret was enabled for this credential. Extensions live at the very end of authData
    /// (after the credential public key), so appending is correct.
    /// </summary>
    internal static byte[] WithHmacSecretRegistrationExtension(byte[] authData)
    {
        // authData layout: rpIdHash(32) | flags(1) | signCount(4) | attestedCredData | extensions
        var ext = CBORObject.NewMap().Add("hmac-secret", true).EncodeToBytes();
        var result = new byte[authData.Length + ext.Length];
        Array.Copy(authData, result, authData.Length);
        Array.Copy(ext, 0, result, authData.Length, ext.Length);
        result[32] |= 0x80; // set ED flag
        return result;
    }

    /// <summary>
    /// Parses <c>{"prf": {"eval": {"first": &lt;32B&gt;, "second": &lt;32B&gt;?}}}</c> from the
    /// extensions map and returns the raw HMAC output bytes (32 for one salt, first||second = 64
    /// for two), or null when no eval salts are present.
    /// </summary>
    internal static byte[]? ComputeHmacPayload(byte[]? extensionsMap)
    {
        if (extensionsMap == null || extensionsMap.Length == 0) return null;
        try
        {
            var map = CBORObject.DecodeFromBytes(extensionsMap);
            if (map.Type != CBORType.Map || !map.ContainsKey("prf")) return null;
            var prf = map["prf"];
            if (prf.Type != CBORType.Map || !prf.ContainsKey("eval")) return null;
            var eval = prf["eval"];
            if (eval.Type != CBORType.Map || !eval.ContainsKey("first")) return null;

            byte[] firstOut = Hmac(eval["first"].GetByteString());
            if (!eval.ContainsKey("second")) return firstOut;

            byte[] secondOut = Hmac(eval["second"].GetByteString());
            var payload = new byte[firstOut.Length + secondOut.Length];
            Array.Copy(firstOut, payload, firstOut.Length);
            Array.Copy(secondOut, 0, payload, firstOut.Length, secondOut.Length);
            return payload;
        }
        catch { return null; }
    }

    /// <summary>
    /// Returns a copy of the assertion authenticatorData with the ED flag set and a
    /// <c>{"hmac-secret": &lt;payload&gt;}</c> CBOR extensions map appended. NOTE: this invalidates
    /// the plugin's signature (which covered the original authData) — it is a probe only, to learn
    /// whether Windows surfaces prf.results from the signed authData extensions. The real
    /// implementation must compute the HMAC plugin-side and sign over the extended authData.
    /// </summary>
    internal static byte[] WithHmacSecretAssertionExtension(byte[] authData, byte[] payload)
    {
        var ext = CBORObject.NewMap().Add("hmac-secret", payload).EncodeToBytes();
        var result = new byte[authData.Length + ext.Length];
        Array.Copy(authData, result, authData.Length);
        Array.Copy(ext, 0, result, authData.Length, ext.Length);
        result[32] |= 0x80; // set ED flag
        return result;
    }

    private static byte[] Hmac(byte[] salt)
    {
        using var h = new HMACSHA256(FixedProbeKey);
        return h.ComputeHash(salt);
    }
}
