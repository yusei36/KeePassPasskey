// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Data.Converters;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Converters;

internal static class ProviderStatusConverters
{
	public static readonly IValueConverter Headline = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
	{
		ProviderStatus.AutoregisterFailed => Strings.App_Status_Headline_AutoregisterFailed,
		ProviderStatus.NotRegistered => Strings.Common_Status_NotRegistered,
		ProviderStatus.WaitingToBeEnabled => Strings.Common_Status_WaitingToBeEnabled,
		ProviderStatus.IncompatibleVersion => Strings.Common_Status_IncompatibleVersion,
		ProviderStatus.VersionMismatch => Strings.Common_Status_VersionMismatch,
		ProviderStatus.NoDatabase => Strings.Common_Status_NoDatabase,
		ProviderStatus.KeePassNotConnected => Strings.Common_Status_KeePassNotConnected,
		_ => Strings.App_Status_Headline_Ready,
	});

	public static readonly IValueConverter ProviderPillText = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
	{
		ProviderStatus.Ready or ProviderStatus.KeePassNotConnected or ProviderStatus.NoDatabase or
		ProviderStatus.VersionMismatch or ProviderStatus.IncompatibleVersion => Strings.App_Status_Pill_Enabled,
		ProviderStatus.WaitingToBeEnabled => Strings.App_Status_Pill_Registered,
		_ => Strings.Common_Status_NotRegistered,
	});

	private static LambdaConverter Make(Func<object?, object?> convert) => new(convert);
}

internal static class PluginPillConverters
{
	public static readonly IValueConverter Text = Make(v => (v as PluginPillState? ?? PluginPillState.NotConnected) switch
	{
		PluginPillState.Running => Strings.App_Status_Pill_Connected,
		PluginPillState.NoDatabase => Strings.Common_Status_NoDatabase,
		PluginPillState.VersionMismatch => Strings.Common_Status_VersionMismatch,
		PluginPillState.IncompatibleVersion => Strings.Common_Status_IncompatibleVersion,
		_ => Strings.App_Status_Pill_NotConnected,
	});

	private static LambdaConverter Make(Func<object?, object?> convert) => new(convert);
}
