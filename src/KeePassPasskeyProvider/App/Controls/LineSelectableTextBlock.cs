// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media.TextFormatting;

namespace KeePassPasskeyProvider.App.Controls;

/// <summary>SelectableTextBlock whose triple-click selects the clicked line, not all text.</summary>
public class LineSelectableTextBlock : SelectableTextBlock
{
	protected override Type StyleKeyOverride => typeof(SelectableTextBlock);

	protected override void OnPointerPressed(PointerPressedEventArgs e)
	{
		var point = e.GetCurrentPoint(this);
		if (point.Properties.IsLeftButtonPressed && e.ClickCount == 3 && SelectLineAt(point.Position))
		{
			e.Handled = true;
			return;
		}
		base.OnPointerPressed(e);
	}

	private bool SelectLineAt(Point position)
	{
		var layout = TextLayout;
		if (layout is null) return false;
		var local = position - new Point(Padding.Left, Padding.Top);
		int index = layout.HitTestPoint(local).TextPosition;
		TextLine? target = null;
		foreach (var line in layout.TextLines)
		{
			target = line;
			if (index < line.FirstTextSourceIndex + line.Length)
				break;
		}
		if (target is null) return false;
		SelectionStart = target.FirstTextSourceIndex;
		SelectionEnd = target.FirstTextSourceIndex + target.Length - target.NewLineLength;
		return true;
	}
}
