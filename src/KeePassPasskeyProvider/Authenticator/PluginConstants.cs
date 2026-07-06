// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Authenticator;

internal static class PluginConstants
{
#if DEBUG
    /// <summary>KeePassPasskey Provider COM server CLSID (dev).</summary>
    public static readonly Guid KeePassPasskeyProviderClsid = new("f048763a-d151-4fb0-b96e-315c543b2431");

    /// <summary>KeePassPasskey Provider AAGUID (dev).</summary>
    public static readonly Guid KeePassPasskeyProviderAaguid = new("56fc5580-c119-4fb8-8964-a1241f2da8ed");
#else
    // Two Release channels: distinct CLSID (avoids COM class collision) selected by the STORE
    // constant (/p:Store=true); shared AAGUID since it names the model, not the instance.
#if STORE
    /// <summary>KeePassPasskey Provider COM server CLSID (Microsoft Store channel).</summary>
    public static readonly Guid KeePassPasskeyProviderClsid = new("281969eb-44a9-4577-954d-b47e72665442");
#else
    /// <summary>KeePassPasskey Provider COM server CLSID (self-signed GitHub channel).</summary>
    public static readonly Guid KeePassPasskeyProviderClsid = new("4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e");
#endif

    /// <summary>KeePassPasskey Provider AAGUID (shared across both Release channels).</summary>
    public static readonly Guid KeePassPasskeyProviderAaguid = new("9addb28c-b46f-4402-808f-019651441ff3");
#endif

    /// <summary>AAGUID as 16 bytes in RFC 4122 big-endian order, for use in authenticatorData and CBOR.</summary>
    public static readonly byte[] KeePassPasskeyProviderAaguidBytes = AaguidToRfc4122Bytes(KeePassPasskeyProviderAaguid);

    private static byte[] AaguidToRfc4122Bytes(Guid guid)
    {
        var bytes = new byte[16];
        guid.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

#if DEBUG
    public const string PluginName      = "KeePassPasskey Dev ";
    public const string ComServerMutexName = @"Local\KeePassPasskeyProvider_COM_Dev";
    public const string ManagementUiMutexName = @"Local\KeePassPasskeyProvider_UI_Dev";
    public const string CacheSyncMutexName = @"Local\KeePassPasskeyProvider_CacheSync_Dev";
#else
    public const string PluginName      = "KeePassPasskey "; // trailing space is to work around Windows quirk where in some contexts the name is not properly displayed
    public const string ComServerMutexName = @"Local\KeePassPasskeyProvider_COM";
    public const string ManagementUiMutexName = @"Local\KeePassPasskeyProvider_UI";
    public const string CacheSyncMutexName = @"Local\KeePassPasskeyProvider_CacheSync";
#endif
    public const string PluginRpId      = "keepasspasskey.github.io";

    public const string StartupTaskTrayApp   = "KeePassPasskeyTrayApp";

    /// <summary>PFNs of the official provider packages.</summary>
    public static readonly string[] OfficialPackageFamilyNames =
    {
        "KeePassPasskeyProvider_rcm79ea08mqe4",       // GitHub channel
        "51133UweKgel.KeePassPasskey_2xyhjw5z6d8g4",  // Store channel
    };

    public static bool IsOfficialPackageFamilyName(string familyName) =>
        Array.Exists(OfficialPackageFamilyNames, n => string.Equals(n, familyName, StringComparison.OrdinalIgnoreCase));
}
