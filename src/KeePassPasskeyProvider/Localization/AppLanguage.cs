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
	/// <summary>Languages with a translation, as neutral culture names. English first.</summary>
	internal static readonly string[] Supported = ["en", "de"];

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

	private static bool IsSupported(CultureInfo culture)
	{
		for (var c = culture; !c.Equals(CultureInfo.InvariantCulture); c = c.Parent)
		{
			if (Array.IndexOf(Supported, c.Name) >= 0)
				return true;
		}
		return false;
	}
}
