// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia.Media;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>
/// Placeholder site/entry icon until real favicons land: first letter on a colour derived from the
/// text, so the same site or entry always looks the same.
/// </summary>
internal static class LetterTile
{
	// Fluent standard accents, all readable with white text in light and dark theme.
	private static readonly IBrush[] Palette =
	[
		new SolidColorBrush(Color.FromRgb(0x0F, 0x6C, 0xBD)),
		new SolidColorBrush(Color.FromRgb(0x87, 0x64, 0xB8)),
		new SolidColorBrush(Color.FromRgb(0xC2, 0x39, 0xB3)),
		new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38)),
		new SolidColorBrush(Color.FromRgb(0xCA, 0x50, 0x10)),
		new SolidColorBrush(Color.FromRgb(0x98, 0x6F, 0x0B)),
		new SolidColorBrush(Color.FromRgb(0x0B, 0x6A, 0x0B)),
		new SolidColorBrush(Color.FromRgb(0x03, 0x83, 0x87)),
	];

	internal static string Letter(string? text)
	{
		if (string.IsNullOrWhiteSpace(text)) return "?";
		foreach (char c in text)
		{
			if (char.IsLetterOrDigit(c))
				return char.ToUpper(c, CultureInfo.CurrentCulture).ToString();
		}
		return "?";
	}

	internal static IBrush Brush(string? text)
	{
		if (string.IsNullOrWhiteSpace(text)) return Palette[0];

		uint hash = 2166136261;
		foreach (char c in text)
			hash = (hash ^ char.ToLowerInvariant(c)) * 16777619;

		return Palette[hash % Palette.Length];
	}
}
