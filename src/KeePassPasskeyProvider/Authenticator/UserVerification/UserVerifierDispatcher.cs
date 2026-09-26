// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal static class UserVerifierDispatcher
{
	private static readonly IUserVerifier _windowsHello = new WindowsHelloUserVerifier();
	private static readonly IUserVerifier _dialog = new DialogUserVerifier();
	private static readonly IUserVerifier _notification = new NotificationUserVerifier();

	// The Notification flag means "confirmation prompt"; the setting only picks how it is presented.
	private static IUserVerifier[] Verifiers =>
	[
		_windowsHello,
		KeePassPasskeySettings.Current.UseLegacyNotificationPrompts ? _notification : _dialog,
	];

	public static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) VerifyForRegistration(
		RegistrationVerification request, bool unlockedNow, CancellationToken cancellation)
		=> DispatchRegistration(EffectiveMode(KeePassPasskeySettings.Current.RegistrationVerification, unlockedNow),
			(IUserVerifier v, out DatabaseInfo? sel, out EntryTargetInfo? selEntry) =>
				v.VerifyForRegistration(request, cancellation, out sel, out selEntry));

	public static int VerifyForSignIn(SignInVerification request, bool unlockedNow, CancellationToken cancellation)
		=> DispatchSignIn(EffectiveMode(KeePassPasskeySettings.Current.SignInVerification, unlockedNow),
			v => v.VerifyForSignIn(request, cancellation));

	/// <summary>
	/// Unlocking KeePass for this very request already verified the user, often with Windows Hello
	/// itself, so a second Windows Hello prompt right after it is dropped. Only while the confirmation
	/// prompt stays on: it names the site and, on registration, picks the target database. Without it,
	/// Windows Hello is the only step that shows which site asked, so it is kept.
	/// </summary>
	private static UserVerificationMode EffectiveMode(UserVerificationMode mode, bool unlockedNow)
	{
		if (!unlockedNow || !mode.HasFlag(UserVerificationMode.WindowsHello)
			|| !mode.HasFlag(UserVerificationMode.Notification)) return mode;
		Log.Info("database was just unlocked, skipping Windows Hello");
		return mode & ~UserVerificationMode.WindowsHello;
	}

	private delegate int VerifyRegistrationFunc(IUserVerifier v, out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry);

	private static (int hr, DatabaseInfo? selectedDatabase, EntryTargetInfo? selectedEntry) DispatchRegistration(
		UserVerificationMode mode, VerifyRegistrationFunc call)
	{
		DatabaseInfo? selected = null;
		EntryTargetInfo? selectedEntry = null;
		foreach (var verifier in Verifiers)
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
		foreach (var verifier in Verifiers)
		{
			if (!mode.HasFlag(verifier.Mode)) continue;
			int hr = call(verifier);
			Log.Info($"verifier={verifier.Mode} hr=0x{hr:X8}");
			if (hr < HResults.S_OK) return hr;
		}
		return HResults.S_OK;
	}
}
