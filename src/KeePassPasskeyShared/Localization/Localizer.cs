// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace KeePassPasskeyShared.Localization;

public static class Localizer
{
	[SuppressMessage("Performance", "CA1863", Justification = "Resource formats change with the language.")]
	public static string Format(string format, params object[] args) =>
		string.Format(CultureInfo.CurrentCulture, format, args);

	public static void Apply(CultureInfo culture)
	{
		EmbeddedResourceManager.Install(typeof(Strings));
		Strings.Culture = culture;
	}
}
