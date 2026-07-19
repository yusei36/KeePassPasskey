// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Authenticator;

/// <summary>Distribution channel a build belongs to; selected at compile time.</summary>
internal enum DistributionChannel
{
	/// <summary>Debug build with the dev identity (CN=KeePassPasskey Dev).</summary>
	Dev,
	/// <summary>Self-signed release published on GitHub.</summary>
	GitHub,
	/// <summary>Release published to the Microsoft Store (/p:Store=true).</summary>
	Store,
}

internal static class PluginConstants
{
#if DEBUG
	/// <summary>KeePassPasskey Provider COM server CLSID (dev).</summary>
	public static readonly Guid KeePassPasskeyProviderClsid = new("f048763a-d151-4fb0-b96e-315c543b2431");

	/// <summary>KeePassPasskey Provider AAGUID (dev).</summary>
	public static readonly Guid KeePassPasskeyProviderAaguid = new("56fc5580-c119-4fb8-8964-a1241f2da8ed");

	/// <summary>Distribution channel of this build.</summary>
	public const DistributionChannel Channel = DistributionChannel.Dev;
#else
	// Two Release channels: distinct CLSID (avoids COM class collision) selected by the STORE
	// constant (/p:Store=true); shared AAGUID since it names the model, not the instance.
#if STORE
	/// <summary>KeePassPasskey Provider COM server CLSID (Microsoft Store channel).</summary>
	public static readonly Guid KeePassPasskeyProviderClsid = new("281969eb-44a9-4577-954d-b47e72665442");

	/// <summary>Distribution channel of this build.</summary>
	public const DistributionChannel Channel = DistributionChannel.Store;
#else
	/// <summary>KeePassPasskey Provider COM server CLSID (self-signed GitHub channel).</summary>
	public static readonly Guid KeePassPasskeyProviderClsid = new("4bff0a65-fdd6-4f97-ac44-7741ecaa5d7e");

	/// <summary>Distribution channel of this build.</summary>
	public const DistributionChannel Channel = DistributionChannel.GitHub;
#endif

	/// <summary>KeePassPasskey Provider AAGUID (shared across both Release channels).</summary>
	public static readonly Guid KeePassPasskeyProviderAaguid = new("9addb28c-b46f-4402-808f-019651441ff3");
#endif

	/// <summary>Readable channel name, appended to copied version strings.</summary>
	public static string ChannelDisplayName => Channel switch
	{
		DistributionChannel.Store => "Microsoft Store",
		DistributionChannel.Dev => "Dev",
		_ => "GitHub",
	};

	/// <summary>Provider log file name</summary>
	public const string ProviderLogFileName = "Provider.log";

	/// <summary>AAGUID as 16 bytes in RFC 4122 big-endian order, for use in authenticatorData and CBOR.</summary>
	public static readonly byte[] KeePassPasskeyProviderAaguidBytes = AaguidToRfc4122Bytes(KeePassPasskeyProviderAaguid);

	/// <summary>Converts a GUID to 16 bytes in RFC 4122 big-endian order (authenticatorData / CBOR layout).</summary>
	internal static byte[] AaguidToRfc4122Bytes(Guid guid)
	{
		var bytes = new byte[16];
		guid.TryWriteBytes(bytes, bigEndian: true, out _);
		return bytes;
	}

#if DEBUG
	public const string PluginName = "KeePassPasskey Dev ";
#else
	public const string PluginName = "KeePassPasskey "; // trailing space is to work around Windows quirk where in some contexts the name is not properly displayed
#endif

	// Named kernel objects (mutexes + the tray "show" event) are namespaced by the MSIX
	// Package Family Name so each installed package (Debug dev / GitHub / Store) gets its own
	// session-local names and the packages can coexist without contending on shared handles.
	private static readonly string SyncObjectBase = ResolveSyncObjectBase();

	private static string ResolveSyncObjectBase()
	{
		try
		{
			return $@"Local\{Windows.ApplicationModel.Package.Current.Id.FamilyName}";
		}
		catch
		{
			// Running unpackaged (no Package.Current): fall back to a fixed base.
			return @"Local\KeePassPasskeyProvider_DEV";
		}
	}

	/// <summary>Single-instance guard for the on-demand COM server.</summary>
	public static readonly string ComServerMutexName = SyncObjectBase + "_COM";
	/// <summary>Single-instance guard for the tray/management app.</summary>
	public static readonly string ManagementUiMutexName = SyncObjectBase + "_UI";
	/// <summary>Cross-process lock serializing Windows credential-cache writes.</summary>
	public static readonly string CacheSyncMutexName = SyncObjectBase + "_CacheSync";
	/// <summary>Event signalling the running management app to show its window.</summary>
	public static readonly string ShowEventName = SyncObjectBase + "_Show";

	public const string PluginRpId = "keepasspasskey.github.io";

	public const string StartupTaskTrayApp = "KeePassPasskeyTrayApp";

	/// <summary>PFNs of the official provider packages.</summary>
	public static readonly string[] OfficialPackageFamilyNames =
	{
		"KeePassPasskeyProvider_rcm79ea08mqe4",       // GitHub channel
		"51133UweKgel.KeePassPasskey_2xyhjw5z6d8g4",  // Store channel
	};

	public static bool IsOfficialPackageFamilyName(string familyName) =>
		Array.Exists(OfficialPackageFamilyNames, n => string.Equals(n, familyName, StringComparison.OrdinalIgnoreCase));
}
