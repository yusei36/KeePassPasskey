// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.Prompts;

/// <summary>
/// The Avalonia application the COM server hosts. Prompt windows only: no lifetime, no main window
/// and no tray icon, so it shares nothing with the management UI's application beyond the settings.
/// </summary>
internal sealed class PromptApplication : Avalonia.Application
{
	public override void Initialize()
	{
		AvaloniaXamlLoader.Load(this);
		RequestedThemeVariant = AppSettings.Current.Theme switch
		{
			Theme.Light => ThemeVariant.Light,
			Theme.Dark => ThemeVariant.Dark,
			_ => ThemeVariant.Default,
		};
	}
}
