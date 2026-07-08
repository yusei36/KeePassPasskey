// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using KeePassPasskeyShared;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Util;

/// <summary>
/// Device-local store for the authenticator identity that is registered with the Windows
/// passkey platform. Kept out of the KeePass database on purpose: it describes this machine's
/// authenticator registration and must be readable at registration time even when KeePass is
/// closed, so syncing it through the shared password database would be surprising.
/// </summary>
internal sealed class AuthenticatorIdentityStore
{
    private static readonly string FilePath = Path.Combine(AppPaths.SettingsDir, "AuthenticatorIdentity.json");

    /// <summary>Spoofed AAGUID as a GUID string, or null/empty to use the built-in default.</summary>
    [JsonProperty("spoofAaguid")]
    public string? SpoofAaguid { get; set; }

    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
    public static AuthenticatorIdentityStore Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return new AuthenticatorIdentityStore();
            return JsonConvert.DeserializeObject<AuthenticatorIdentityStore>(File.ReadAllText(FilePath))
                   ?? new AuthenticatorIdentityStore();
        }
        catch
        {
            return new AuthenticatorIdentityStore();
        }
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
    public static void Save(AuthenticatorIdentityStore store)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.SettingsDir);
            string tmp = FilePath + $".{Environment.ProcessId}.tmp";
            File.WriteAllText(tmp, JsonConvert.SerializeObject(store, Formatting.Indented));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"AuthenticatorIdentityStore.Save failed: {ex.Message}");
        }
    }
}
