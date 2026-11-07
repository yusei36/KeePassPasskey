// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Data.Converters;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.Converters;

internal static class AlgorithmSelectionModeConverters
{
	public static readonly IValueConverter Text = new LambdaConverter(v => (v as AlgorithmSelectionMode?) switch
	{
		AlgorithmSelectionMode.RelyingPartyOrder => Strings.App_Settings_Algorithms_OptionWebsiteOrder,
		_ => Strings.App_Settings_Algorithms_OptionListOrder,
	});
}
