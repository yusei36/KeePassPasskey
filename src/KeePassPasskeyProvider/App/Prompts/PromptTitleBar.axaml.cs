// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Input;

namespace KeePassPasskeyProvider.App.Prompts;

public partial class PromptTitleBar : UserControl
{
	public PromptTitleBar() => InitializeComponent();

	// The close button handles its own press, so a click on it never reaches here and never drags.
	protected override void OnPointerPressed(PointerPressedEventArgs e)
	{
		base.OnPointerPressed(e);

		if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed
			&& TopLevel.GetTopLevel(this) is Window window)
			window.BeginMoveDrag(e);
	}
}
