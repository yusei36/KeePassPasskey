// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections;
using System.Globalization;
using Avalonia.Media;

namespace KeePassPasskeyProvider.Localization;

/// <summary>
/// Workaround for Avalonia's font fallback, which picks the font for characters the UI font lacks
/// (Chinese, Japanese) once, with the culture current at that moment, and caches it for the process
/// (AvaloniaUI/Avalonia#22464). A live language switch therefore kept the old language's glyph shapes
/// until a restart. This list names the font per app language instead; Avalonia holds it by reference
/// and checks it before its cache, so <see cref="Apply"/> takes effect for any text laid out afterwards.
/// Remove it once Avalonia's fallback respects the culture.
/// </summary>
internal sealed class AppFontFallbacks : IReadOnlyList<FontFallback>
{
	internal static readonly AppFontFallbacks Instance = new();

	private volatile FontFallback[] _items = [];

	private AppFontFallbacks()
	{
	}

	internal static FontManagerOptions Options => new() { FontFallbacks = Instance };

	internal void Apply(CultureInfo culture)
	{
		string? family = FamilyFor(culture);
		_items = family == null ? [] : [new FontFallback { FontFamily = new FontFamily(family) }];
	}

	private static string? FamilyFor(CultureInfo culture)
	{
		for (var c = culture; !c.Equals(CultureInfo.InvariantCulture); c = c.Parent)
		{
			// Hard-coded workaround until Avalonia's fallback respects the culture (AvaloniaUI/Avalonia#22464):
			// every further CJK language (e.g. Korean, Traditional Chinese) needs its own case here.
			switch (c.Name)
			{
				case "zh-Hans":
					return "Microsoft YaHei UI";
				case "ja":
					return "Yu Gothic UI";
			}
		}
		return null;
	}

	public FontFallback this[int index] => _items[index];

	public int Count => _items.Length;

	public IEnumerator<FontFallback> GetEnumerator() => ((IEnumerable<FontFallback>)_items).GetEnumerator();

	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
