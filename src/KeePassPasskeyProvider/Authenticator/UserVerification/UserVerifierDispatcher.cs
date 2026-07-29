// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal static class UserVerifierDispatcher
{
	// The Notification flag means "confirmation prompt", now rendered as a dialog.
	// NotificationUserVerifier is kept unwired for the upcoming presentation setting.
	private static readonly IUserVerifier[] _verifiers =
	[
		new WindowsHelloUserVerifier(),
		new DialogUserVerifier(),
	];

	public static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) VerifyForRegistration(
		nint pRequest, Guid transactionId,
		string rpId, string rpName, string uvUsername, string uvDisplayHint,
		IReadOnlyList<DatabaseInfo> databases, IReadOnlyList<EntryMatchInfo> candidateEntries,
		CancellationToken cancellation)
		=> DispatchRegistration(KeePassPasskeySettings.Current.RegistrationVerification,
			(IUserVerifier v, out DatabaseInfo? sel, out EntryTargetInfo? selEntry) =>
				v.VerifyForRegistration(pRequest, rpId, rpName, uvUsername, uvDisplayHint, transactionId, databases, candidateEntries, cancellation, out sel, out selEntry));

	public static int VerifyForSignIn(
		nint pRequest, Guid transactionId,
		string rpId, string uvUsername, string uvDisplayHint,
		CancellationToken cancellation)
		=> DispatchSignIn(KeePassPasskeySettings.Current.SignInVerification,
			v => v.VerifyForSignIn(pRequest, rpId, uvUsername, uvDisplayHint, transactionId, cancellation));

	private delegate int VerifyRegistrationFunc(IUserVerifier v, out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry);

	private static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) DispatchRegistration(
		UserVerificationMode mode, VerifyRegistrationFunc call)
	{
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
