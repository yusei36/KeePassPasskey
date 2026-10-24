// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

/// <summary>What a verifier needs to confirm a registration ceremony.</summary>
/// <param name="RequestPtr">The platform's WEBAUTHN_PLUGIN_OPERATION_REQUEST, for the owner window.</param>
internal sealed record RegistrationVerification(
	nint RequestPtr,
	Guid TransactionId,
	string RpId,
	string UserName,
	IReadOnlyList<DatabaseInfo> Databases,
	IReadOnlyList<EntryMatchInfo> CandidateEntries,
	bool EnterpriseAttestationRequested);

/// <summary>What a verifier needs to confirm a sign-in ceremony.</summary>
/// <param name="RequestPtr">The platform's WEBAUTHN_PLUGIN_OPERATION_REQUEST, for the owner window.</param>
internal sealed record SignInVerification(
	nint RequestPtr,
	Guid TransactionId,
	string RpId,
	string UserName,
	string? EntryTitle = null,
	string? DatabaseName = null,
	string? Icon = null);
