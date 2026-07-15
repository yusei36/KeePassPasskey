// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Data.Converters;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.Converters;

internal static class PasskeyEntryGroupModeConverters
{
	public static readonly IValueConverter Text = new LambdaConverter(v => (v as PasskeyEntryGroupMode?) switch
	{
		PasskeyEntryGroupMode.SelectedGroup => "Selected group",
		_ => "Passkeys group",
	});
}
