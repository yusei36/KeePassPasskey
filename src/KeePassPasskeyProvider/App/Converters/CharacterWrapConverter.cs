// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text;
using Avalonia.Data.Converters;

namespace KeePassPasskeyProvider.App.Converters;

/// <summary>Inserts a zero-width space after every character so TextWrapping="Wrap" breaks character-by-character.</summary>
internal sealed class CharacterWrapConverter : IValueConverter
{
	public static readonly CharacterWrapConverter Instance = new();

	private const char ZeroWidthSpace = (char)0x200B;

	public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
	{
		if (value is not string s || s.Length == 0)
			return value;

		var sb = new StringBuilder(s.Length * 2);
		foreach (char c in s)
		{
			sb.Append(c);
			sb.Append(ZeroWidthSpace);
		}
		return sb.ToString();
	}

	public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
		=> throw new NotSupportedException();
}
