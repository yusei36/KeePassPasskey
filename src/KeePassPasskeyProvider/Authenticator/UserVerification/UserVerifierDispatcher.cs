// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal static class UserVerifierDispatcher
{
	private static readonly IUserVerifier[] _verifiers =
	[
		new WindowsHelloUserVerifier(),
		new NotificationUserVerifier(),
	];

	public static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) VerifyForRegistration(
		nint pRequest, Guid transactionId,
		string rpId, string rpName, string uvUsername, string uvDisplayHint,
		IReadOnlyList<DatabaseInfo> databases, IReadOnlyList<EntryMatchInfo> candidateEntries)
		=> DispatchRegistration(KeePassPasskeySettings.Current.RegistrationVerification,
			(IUserVerifier v, out DatabaseInfo? sel, out EntryTargetInfo? selEntry) =>
				v.VerifyForRegistration(pRequest, rpId, rpName, uvUsername, uvDisplayHint, transactionId, databases, candidateEntries, out sel, out selEntry));

	public static int VerifyForSignIn(
		nint pRequest, Guid transactionId,
		string rpId, string uvUsername, string uvDisplayHint)
		=> DispatchSignIn(KeePassPasskeySettings.Current.SignInVerification,
			v => v.VerifyForSignIn(pRequest, rpId, uvUsername, uvDisplayHint, transactionId));

	private delegate int VerifyRegistrationFunc(IUserVerifier v, out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry);

	private static bool AreNotificationsDisabled(UserVerificationMode mode)
	{
		if (!mode.HasFlag(UserVerificationMode.Notification)) return false;

		var setting = ToastNotificationManagerCompat.CreateToastNotifier().Setting;
		if (setting == NotificationSetting.Enabled) return false;

		Log.Warn($"Notifications disabled ({setting}); verification failed", nameof(UserVerifierDispatcher));
		return true;
	}

	private static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) DispatchRegistration(
		UserVerificationMode mode, VerifyRegistrationFunc call)
	{
		if (AreNotificationsDisabled(mode)) return (HResults.E_FAIL, null, null);

		DatabaseInfo? selected = null;
		EntryTargetInfo? selectedEntry = null;
		foreach (var verifier in _verifiers)
		{
			if (!mode.HasFlag(verifier.Mode)) continue;
			int hr = call(verifier, out DatabaseInfo? sel, out EntryTargetInfo? selEntry);
			Log.Info($"verifier={verifier.Mode} hr=0x{hr:X8}");
			if (sel != null) selected = sel;
			if (selEntry != null) selectedEntry = selEntry;
			if (hr < HResults.S_OK) return (hr, null, null);
		}
		return (HResults.S_OK, selected, selectedEntry);
	}

	private static int DispatchSignIn(UserVerificationMode mode, Func<IUserVerifier, int> call)
	{
		if (AreNotificationsDisabled(mode)) return HResults.E_FAIL;

		foreach (var verifier in _verifiers)
		{
			if (!mode.HasFlag(verifier.Mode)) continue;
			int hr = call(verifier);
			Log.Info($"verifier={verifier.Mode} hr=0x{hr:X8}");
			if (hr < HResults.S_OK) return hr;
		}
		return HResults.S_OK;
	}
}
