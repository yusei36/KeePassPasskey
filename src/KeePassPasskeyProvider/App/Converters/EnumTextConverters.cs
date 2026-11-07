// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Data.Converters;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.Converters;

internal static class ThemeConverters
{
	public static readonly IValueConverter Text = new LambdaConverter(v => (v as Theme?) switch
	{
		Theme.Light => Strings.App_Settings_Theme_OptionLight,
		Theme.Dark => Strings.App_Settings_Theme_OptionDark,
		_ => Strings.App_Settings_Theme_OptionSystem,
	});
}

internal static class LogLevelConverters
{
	public static readonly IValueConverter Text = new LambdaConverter(v => (v as LogLevel?) switch
	{
		LogLevel.Debug => Strings.App_Settings_LogLevel_OptionDebug,
		LogLevel.Info => Strings.App_Settings_LogLevel_OptionInfo,
		LogLevel.Warn => Strings.App_Settings_LogLevel_OptionWarn,
		LogLevel.Error => Strings.App_Settings_LogLevel_OptionError,
		_ => Strings.App_Settings_LogLevel_OptionOff,
	});
}
