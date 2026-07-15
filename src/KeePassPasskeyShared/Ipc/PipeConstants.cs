// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;

namespace KeePassPasskeyShared.Ipc;

public static class PipeConstants
{
#if DEBUG
	public const string PipeName = "keepass-passkey-provider-dev";
#else
	public const string PipeName = "keepass-passkey-provider";
#endif

	/// <summary>
	/// Protocol version gating the ping handshake, independent of the product version.
	/// Should be bumped for breaking pipe changes, doesn't need to be bumped for additive optional fields.
	/// </summary>
	public const int ProtocolVersion = 1;

	public static readonly string Version =
		Assembly.GetExecutingAssembly()
			.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
			?.InformationalVersion ?? "unknown";

	/// <summary>Removes SemVer build metadata (everything from the first '+') from a version string.</summary>
	public static string StripBuildMetadata(string version)
	{
		if (string.IsNullOrEmpty(version)) return version;
		var plus = version.IndexOf('+');
		return plus >= 0 ? version.Substring(0, plus) : version;
	}

	/// <summary>
	/// Orders two product version strings; 0 when either numeric part does not parse.
	/// When the numeric parts are equal, a pre-release (e.g. "1.4.0-rc1") is older than the
	/// matching final release ("1.4.0"), so the older side can still be identified.
	/// </summary>
	public static int CompareProductVersions(string a, string b)
	{
		var va = ParseNumericVersion(a);
		var vb = ParseNumericVersion(b);
		if (va == null || vb == null) return 0;
		var numeric = va.CompareTo(vb);
		return numeric != 0 ? numeric : ComparePreRelease(PreReleaseTag(a), PreReleaseTag(b));
	}

	private static System.Version ParseNumericVersion(string version)
	{
		if (string.IsNullOrEmpty(version)) return null;
		var s = StripBuildMetadata(version);
		var dash = s.IndexOf('-');
		if (dash >= 0) s = s.Substring(0, dash);
		if (s.IndexOf('.') < 0) s += ".0";
		return System.Version.TryParse(s, out var v) ? v : null;
	}

	/// <summary>The SemVer pre-release tag (between '-' and '+'), or "" for a final release.</summary>
	private static string PreReleaseTag(string version)
	{
		var s = StripBuildMetadata(version ?? "");
		var dash = s.IndexOf('-');
		return dash >= 0 ? s.Substring(dash + 1) : "";
	}

	/// <summary>SemVer precedence: a final release outranks any pre-release; otherwise ordinal.</summary>
	private static int ComparePreRelease(string a, string b)
	{
		if (a == b) return 0;
		if (a.Length == 0) return 1;   // a is final, b is pre-release  -> a newer
		if (b.Length == 0) return -1;  // b is final, a is pre-release  -> a older
		return System.Math.Sign(string.CompareOrdinal(a, b));
	}
}
