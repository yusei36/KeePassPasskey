// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>
/// Sets a TextBlock from one translatable sentence in which **marked** parts (file names, UI
/// labels) are shown in a monospace, semibold run, so translators can move them freely.
/// </summary>
/// <remarks>
/// Text the run's own font has no glyphs for (Chinese, for example) gets its own run with the
/// fallback family set explicitly. Left to Avalonia, the fallback first reuses the typeface the
/// previous run fell back to, weight included, so a marked part's semibold carried over into the
/// plain text after it and the plain text's regular weight into the marked part.
/// </remarks>
public static class MarkedText
{
	private const string Marker = "**";
	private static readonly FontFamily Mono = new("Consolas,Courier New,monospace");

	public static readonly AttachedProperty<string?> TextProperty =
		AvaloniaProperty.RegisterAttached<TextBlock, string?>("Text", typeof(MarkedText));

	static MarkedText()
	{
		TextProperty.Changed.AddClassHandler<TextBlock>((block, _) => Apply(block));
		// The plain runs use the TextBlock's own font, which is only final once styles and inherited
		// values apply, so the fallback runs are worked out again when it changes.
		TextBlock.FontFamilyProperty.Changed.AddClassHandler<TextBlock>(Reapply);
		TextBlock.FontWeightProperty.Changed.AddClassHandler<TextBlock>(Reapply);
		TextBlock.FontStyleProperty.Changed.AddClassHandler<TextBlock>(Reapply);
		TextBlock.FontStretchProperty.Changed.AddClassHandler<TextBlock>(Reapply);
	}

	public static string? GetText(TextBlock block) => block.GetValue(TextProperty);

	public static void SetText(TextBlock block, string? value) => block.SetValue(TextProperty, value);

	private static void Reapply(TextBlock block, AvaloniaPropertyChangedEventArgs e)
	{
		if (GetText(block) != null)
			Apply(block);
	}

	private static void Apply(TextBlock block)
	{
		var inlines = new InlineCollection();
		string[] parts = (GetText(block) ?? "").Split(Marker);
		for (int i = 0; i < parts.Length; i++)
		{
			if (parts[i].Length == 0)
				continue;
			bool marked = i % 2 == 1;
			var family = marked ? Mono : block.FontFamily;
			var weight = marked ? FontWeight.SemiBold : block.FontWeight;
			foreach (var (text, fallback) in SplitByFont(parts[i], new Typeface(family, block.FontStyle, weight, block.FontStretch)))
			{
				var run = new Run(text);
				if (marked)
				{
					run.FontFamily = fallback ?? Mono;
					run.FontWeight = FontWeight.SemiBold;
				}
				else if (fallback != null)
				{
					run.FontFamily = fallback;
				}
				inlines.Add(run);
			}
		}
		block.Inlines = inlines;
	}

	/// <summary>
	/// Splits text into pieces the typeface can show (fallback null) and pieces that need a fallback
	/// family. Spaces, marks and format characters stay with the piece they follow.
	/// </summary>
	private static List<(string Text, FontFamily? Fallback)> SplitByFont(string text, Typeface typeface)
	{
		var pieces = new List<(string, FontFamily?)>();
		var fontManager = FontManager.Current;
		if (!fontManager.TryGetGlyphTypeface(typeface, out var primary))
		{
			pieces.Add((text, null));
			return pieces;
		}

		var culture = CultureInfo.CurrentUICulture;
		FontFamily? current = null;
		GlyphTypeface? currentGlyphs = null;
		int start = 0;
		for (int i = 0; i < text.Length;)
		{
			Rune.DecodeFromUtf16(text.AsSpan(i), out var rune, out int length);
			FontFamily? wanted = current;
			if (NeedsGlyph(rune))
			{
				if (primary.CharacterToGlyphMap.ContainsGlyph(rune.Value))
				{
					wanted = null;
				}
				else if (currentGlyphs == null || !currentGlyphs.CharacterToGlyphMap.ContainsGlyph(rune.Value))
				{
					wanted = fontManager.TryMatchCharacter(rune.Value, typeface.Style, typeface.Weight, typeface.Stretch,
						typeface.FontFamily, culture, out var match) ? match.FontFamily : null;
				}
			}

			if (!Equals(wanted, current))
			{
				if (i > start)
					pieces.Add((text[start..i], current));
				start = i;
				current = wanted;
				currentGlyphs = null;
				if (current != null && fontManager.TryGetGlyphTypeface(
						new Typeface(current, typeface.Style, typeface.Weight, typeface.Stretch), out var glyphs))
					currentGlyphs = glyphs;
			}
			i += length;
		}
		pieces.Add((text[start..], current));
		return pieces;
	}

	private static bool NeedsGlyph(Rune rune) => Rune.GetUnicodeCategory(rune) is not (
		UnicodeCategory.SpaceSeparator or UnicodeCategory.Control or UnicodeCategory.Format
		or UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark);
}
