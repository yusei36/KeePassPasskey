// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using KeePassPasskeyShared.Localization;

namespace KeePassPasskeyProvider.Localization;

/// <summary>
/// The app's UI language: the one chosen in Settings, otherwise the Windows display language when
/// we have it, otherwise English.
/// </summary>
internal static class AppLanguage
{
	private static readonly CultureInfo SystemCulture = CultureInfo.CurrentUICulture;

	/// <summary>Raised on the UI thread after the language changed at runtime.</summary>
	internal static event EventHandler? Changed;

	private static CultureInfo _current = CultureInfo.GetCultureInfo("en");

	/// <param name="language">A stored culture name, or null for the Windows language.</param>
	internal static CultureInfo Resolve(string? language)
	{
		if (!string.IsNullOrEmpty(language))
		{
			try
			{
				var chosen = CultureInfo.GetCultureInfo(language);
				if (IsSupported(chosen))
					return chosen;
			}
			catch (CultureNotFoundException)
			{
			}
		}
		return IsSupported(SystemCulture) ? SystemCulture : CultureInfo.GetCultureInfo("en");
	}

	internal static void Apply(string? language)
	{
		var culture = Resolve(language);
		Localizer.Apply(culture);

		bool changed = !culture.Equals(_current);
		_current = culture;
		if (changed)
			Changed?.Invoke(null, EventArgs.Empty);
	}

	/// <summary>A language's name in that language, so it can be found while the UI is in another.</summary>
	internal static string NativeName(string cultureName)
	{
		var culture = CultureInfo.GetCultureInfo(cultureName);
		string name = culture.NativeName;
		return name.Length > 0 ? char.ToUpper(name[0], culture) + name[1..] : cultureName;
	}

	/// <summary>False while the language in use is a translation no native speaker has checked.</summary>
	internal static bool IsCurrentReviewed => Find(_current)?.Reviewed ?? true;

	private static bool IsSupported(CultureInfo culture) => Find(culture) != null;

	private static SupportedLanguage? Find(CultureInfo culture)
	{
		for (var c = culture; !c.Equals(CultureInfo.InvariantCulture); c = c.Parent)
		{
			if (SupportedLanguages.All.FirstOrDefault(l => l.Tag == c.Name) is { } language)
				return language;
		}
		return null;
	}
}
