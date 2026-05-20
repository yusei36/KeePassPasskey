// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

internal interface IUserVerifier
{
    UserVerificationMode Mode { get; }
    int VerifyForRegistration(nint pRequest, string rpId, string rpName, string username, string displayHint,
        Guid transactionId, IReadOnlyList<DatabaseInfo> databases, out string? selectedDatabaseId);
    int VerifyForSignIn(nint pRequest, string rpId, string username, string displayHint, Guid transactionId);
}
