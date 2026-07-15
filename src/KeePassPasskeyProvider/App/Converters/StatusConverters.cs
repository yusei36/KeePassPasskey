// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia.Data.Converters;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Converters;

internal static class ProviderStatusConverters
{
	public static readonly IValueConverter Headline = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
	{
		ProviderStatus.AutoregisterFailed => "Automatic registration failed",
		ProviderStatus.NotRegistered => "Not registered",
		ProviderStatus.WaitingToBeEnabled => "Waiting to be enabled",
		ProviderStatus.IncompatibleVersion => "Incompatible version",
		ProviderStatus.VersionMismatch => "Version mismatch",
		ProviderStatus.NoDatabase => "No database open",
		ProviderStatus.KeePassNotConnected => "KeePass not connected",
		_ => "All systems ready",
	});

	public static readonly IValueConverter ProviderPillText = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
	{
		ProviderStatus.Ready or ProviderStatus.KeePassNotConnected or ProviderStatus.NoDatabase or
		ProviderStatus.VersionMismatch or ProviderStatus.IncompatibleVersion => "Enabled",
		ProviderStatus.WaitingToBeEnabled => "Registered",
		_ => "Not registered",
	});

	private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}

internal static class PluginPillConverters
{
	public static readonly IValueConverter Text = Make(v => (v as PluginPillState? ?? PluginPillState.NotConnected) switch
	{
		PluginPillState.Running => "Running",
		PluginPillState.NoDatabase => "No database open",
		PluginPillState.VersionMismatch => "Version mismatch",
		PluginPillState.IncompatibleVersion => "Incompatible version",
		_ => "Not connected",
	});

	private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}

internal static class UserVerificationModeConverters
{
	public static readonly IValueConverter Text = Make(v => (v as UserVerificationMode?) switch
	{
		UserVerificationMode.WindowsHello => "Windows Hello",
		UserVerificationMode.Notification => "Notification",
		UserVerificationMode.Both => "Both",
		_ => "None",
	});

	private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}
