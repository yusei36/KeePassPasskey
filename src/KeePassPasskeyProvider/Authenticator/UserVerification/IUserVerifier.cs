// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal interface IUserVerifier
{
	UserVerificationMode Mode { get; }
	int VerifyForRegistration(RegistrationVerification request, CancellationToken cancellation,
		out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry);
	int VerifyForSignIn(SignInVerification request, CancellationToken cancellation);
}
