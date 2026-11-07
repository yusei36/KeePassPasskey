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
	internal static void Apply() => Localizer.Apply(Resolve(ReadKeePassLanguage()));

	/// <summary>An unknown or empty code (no translation loaded) means English.</summary>
	internal static CultureInfo Resolve(string iso6391Code)
	{
		if (string.IsNullOrEmpty(iso6391Code))
			return CultureInfo.GetCultureInfo("en");
		try
		{
			return CultureInfo.GetCultureInfo(iso6391Code);
		}
		catch (CultureNotFoundException)
		{
			return CultureInfo.GetCultureInfo("en");
		}
	}

	private static string ReadKeePassLanguage()
	{
		try
		{
			return KeePass.Program.Translation?.Properties?.Iso6391Code;
		}
		catch (Exception ex)
		{
			Log.Warn("could not read the KeePass UI language: " + ex.Message);
			return null;
		}
	}
}
