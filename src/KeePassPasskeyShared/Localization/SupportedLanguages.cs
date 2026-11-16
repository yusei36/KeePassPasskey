// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;

namespace KeePassPasskeyShared.Localization;

public sealed class SupportedLanguage
{
	public SupportedLanguage(string tag, string keePassCode, bool reviewed)
	{
		Tag = tag;
		KeePassCode = keePassCode;
		Reviewed = reviewed;
	}

	/// <summary>Language tag as .NET spells it; also the <c>Strings.&lt;tag&gt;.resx</c> file name.</summary>
	public string Tag { get; }

	/// <summary>The Iso6391Code of the KeePass translation, which is not always a language tag.</summary>
	public string KeePassCode { get; }

	/// <summary>A native speaker has checked the translation; the app marks the others as not yet reviewed.</summary>
	public bool Reviewed { get; }
}

/// <summary>
/// Every language with a translation. The app lists them by tag, the plugin finds its language by
/// the KeePass code.
/// </summary>
public static class SupportedLanguages
{
	// English first, then sorted by tag, one per line: language branches then merge without conflicts.
	public static readonly IReadOnlyList<SupportedLanguage> All = new[]
	{
		new SupportedLanguage("en", "en", reviewed: true),
		new SupportedLanguage("de", "de", reviewed: true),
		new SupportedLanguage("es", "es", reviewed: false),
		new SupportedLanguage("fr", "fr", reviewed: false),
		new SupportedLanguage("it", "it", reviewed: false),
	};

	/// <returns>The tag of the language KeePass runs in, or null when we have no translation for it.</returns>
	public static string FromKeePass(string iso6391Code)
	{
		if (string.IsNullOrEmpty(iso6391Code))
			return null;
		foreach (var language in All)
		{
			if (string.Equals(language.KeePassCode, iso6391Code, StringComparison.OrdinalIgnoreCase))
				return language.Tag;
		}
		return null;
	}
}
