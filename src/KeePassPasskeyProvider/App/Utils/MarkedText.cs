// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>
/// Sets a TextBlock from one translatable sentence in which **marked** parts (file names, UI
/// labels) are shown in a monospace, semibold run, so translators can move them freely.
/// </summary>
public static class MarkedText
{
	private const string Marker = "**";
	private static readonly FontFamily Mono = new("Consolas,Courier New,monospace");

	public static readonly AttachedProperty<string?> TextProperty =
		AvaloniaProperty.RegisterAttached<TextBlock, string?>("Text", typeof(MarkedText));

	static MarkedText()
	{
		TextProperty.Changed.AddClassHandler<TextBlock>((block, e) => Apply(block, e.NewValue as string));
	}

	public static string? GetText(TextBlock block) => block.GetValue(TextProperty);

	public static void SetText(TextBlock block, string? value) => block.SetValue(TextProperty, value);

	private static void Apply(TextBlock block, string? text)
	{
		var inlines = new InlineCollection();
		string[] parts = (text ?? "").Split(Marker);
		for (int i = 0; i < parts.Length; i++)
		{
			if (parts[i].Length == 0)
				continue;
			var run = new Run(parts[i]);
			if (i % 2 == 1)
			{
				run.FontFamily = Mono;
				run.FontWeight = FontWeight.SemiBold;
			}
			inlines.Add(run);
		}
		block.Inlines = inlines;
	}
}
