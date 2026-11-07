// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Globalization;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Localization;

namespace KeePassPasskey.Localization;

/// <summary>
/// Follows KeePass's UI language rather than the Windows one. Only our own strings are pointed at
/// it; KeePass's thread cultures are left alone.
/// </summary>
internal static class PluginLanguage
{
	internal static void Apply()
	{
		var properties = ReadKeePassLanguage();
		Localizer.Apply(Resolve(properties.Code, properties.NameEnglish));
	}

	/// <summary>An unknown or empty code (no translation loaded) means English.</summary>
	internal static CultureInfo Resolve(string iso6391Code, string nameEnglish)
	{
		if (string.IsNullOrEmpty(iso6391Code))
			return CultureInfo.GetCultureInfo("en");
		try
		{
			return CultureInfo.GetCultureInfo(WithScript(iso6391Code, nameEnglish ?? ""));
		}
		catch (CultureNotFoundException)
		{
			return CultureInfo.GetCultureInfo("en");
		}
	}

	// KeePass reports Simplified Chinese as plain "zh" (Traditional is "zh-tw") and both Serbian
	// scripts as "sr", so the script comes from here; a "zh" translation would also reach zh-TW.
	private static string WithScript(string code, string nameEnglish)
	{
		if (string.Equals(code, "zh", StringComparison.OrdinalIgnoreCase))
			return "zh-Hans";
		if (string.Equals(code, "sr", StringComparison.OrdinalIgnoreCase))
			return nameEnglish.IndexOf("Latin", StringComparison.OrdinalIgnoreCase) >= 0 ? "sr-Latn" : "sr-Cyrl";
		return code;
	}

	private static (string Code, string NameEnglish) ReadKeePassLanguage()
	{
		try
		{
			var properties = KeePass.Program.Translation?.Properties;
			return (properties?.Iso6391Code, properties?.NameEnglish);
		}
		catch (Exception ex)
		{
			Log.Warn("could not read the KeePass UI language: " + ex.Message);
			return (null, null);
		}
	}
}
