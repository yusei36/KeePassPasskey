// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Resolves the authenticator identity that is advertised to Windows and to relying parties.
/// The AAGUID can be overridden (spoofed) via <see cref="AuthenticatorSettingsStore"/>; when no
/// valid override is stored, the built-in <see cref="PluginConstants"/> default is used.
/// </summary>
internal static class AuthenticatorIdentity
{
	/// <summary>The built-in AAGUID for this build (Release or dev).</summary>
	public static Guid DefaultAaguid => PluginConstants.KeePassPasskeyProviderAaguid;

	/// <summary>
	/// The AAGUID to advertise: the stored spoof value when it is a valid GUID and spoofing is allowed,
	/// otherwise the default.
	/// </summary>
	public static Guid EffectiveAaguid =>
		KeePassPasskeySettings.Current.AllowAaguidSpoofing
		&& TryParseStoredAaguid(AuthenticatorSettingsStore.Load().SpoofAaguid, out Guid g) ? g : DefaultAaguid;

	/// <summary>The effective AAGUID as 16 bytes in RFC 4122 big-endian order.</summary>
	public static byte[] EffectiveAaguidBytes => PluginConstants.AaguidToRfc4122Bytes(EffectiveAaguid);

	/// <summary>True when a valid spoof AAGUID is stored, i.e. the effective value differs from the default.</summary>
	public static bool IsAaguidSpoofed => EffectiveAaguid != DefaultAaguid;

	/// <summary>
	/// With spoofing turned off by configuration, puts the default back in Windows and drops the stored
	/// override. Only acts once, since the store is empty afterwards.
	/// </summary>
	public static void RestoreDefaultIfSpoofingDisallowed()
	{
		if (KeePassPasskeySettings.Current.AllowAaguidSpoofing) return;
		if (!TryParseStoredAaguid(AuthenticatorSettingsStore.Load().SpoofAaguid, out _)) return;

		int hr = PluginRegistration.UpdateDetails(DefaultAaguid);
		if (hr < Native.HResults.S_OK)
		{
			Log.Warn($"AAGUID spoofing is disabled, but restoring the default AAGUID failed: 0x{hr:X8}");
			return;
		}
		AuthenticatorSettingsStore.Save(new AuthenticatorSettingsStore());
		Log.Info("AAGUID spoofing is disabled; restored the default AAGUID");
	}

	/// <summary>
	/// Parses a stored AAGUID string. Empty/whitespace is treated as "use default" and returns false.
	/// </summary>
	public static bool TryParseStoredAaguid(string? stored, out Guid aaguid)
	{
		if (!string.IsNullOrWhiteSpace(stored) && Guid.TryParse(stored, out aaguid))
			return true;
		aaguid = Guid.Empty;
		return false;
	}
}
