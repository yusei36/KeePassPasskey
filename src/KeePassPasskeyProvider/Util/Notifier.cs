// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Toolkit.Uwp.Notifications;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Util;

internal static class Notifier
{
	private static bool Enabled => KeePassPasskeySettings.Current.ShowErrorNotifications;

	public static void ShowMakeCredentialError(string rpId, PipeErrorCode? code, string? errorMessage = null) =>
		ShowError(Strings.Notify_Title_CreateFailed, ErrorBody(code, rpId, errorMessage));

	public static void ShowGetAssertionError(string rpId, string username, PipeErrorCode? code, string? errorMessage = null) =>
		ShowError(Strings.Notify_Title_SignInFailed, ErrorBody(code, rpId, errorMessage, username));

	public static void ShowPipeError(string failureTitle) =>
		ShowError(failureTitle, Strings.Notify_Error_KeePassNotReady);

	public static void ShowVersionMismatch(string failureTitle, string? appVersion, string? pluginVersion) =>
		ShowError(failureTitle, VersionMismatchBody(appVersion, pluginVersion));

	internal static string VersionMismatchBody(string? appVersion, string? pluginVersion)
	{
		string app = PipeConstants.StripBuildMetadata(appVersion ?? "");
		string plugin = PipeConstants.StripBuildMetadata(pluginVersion ?? "");
		int cmp = PipeConstants.CompareProductVersions(appVersion, pluginVersion);
		if (cmp > 0)
			return Localizer.Format(Strings.Common_Version_PluginOlder, plugin, app);
		if (cmp < 0)
			return Localizer.Format(Strings.Common_Version_AppOlder, app, plugin);
		return Strings.Common_Version_Incompatible;
	}

	private static string ErrorBody(PipeErrorCode? code, string rpId, string? errorMessage, string username = "")
	{
		// The plugin's errorMessage is English diagnostics, so it is only appended where no code says more.
		var detail = string.IsNullOrWhiteSpace(errorMessage) ? "" : $"\n{errorMessage}";
		return code switch
		{
			PipeErrorCode.DbLocked => Strings.Notify_Error_DbLocked,
			PipeErrorCode.Duplicate => Localizer.Format(Strings.Notify_Error_Duplicate, rpId),
			PipeErrorCode.NotFound => username.Length > 0
				? Localizer.Format(Strings.Notify_Error_NotFoundForUser, username, rpId)
				: Localizer.Format(Strings.Notify_Error_NotFound, rpId),
			PipeErrorCode.UnsupportedAlgorithm => Strings.Notify_Error_UnsupportedAlgorithm,
			PipeErrorCode.IncompatibleVersion => Strings.Common_Version_Incompatible,
			PipeErrorCode.InternalError => Strings.Notify_Error_Internal + detail,
			_ => Strings.Notify_Error_Unexpected + detail,
		};
	}

	private static void ShowError(string title, string body)
	{
		if (!Enabled) return;
		try
		{
			new ToastContentBuilder()
				.AddText(title)
				.AddText(body)
				.Show(toast => toast.ExpirationTime = DateTimeOffset.Now.AddSeconds(30));
		}
		catch (Exception ex)
		{
			Log.Warn($"toast failed: {ex.Message}");
		}
	}
}
