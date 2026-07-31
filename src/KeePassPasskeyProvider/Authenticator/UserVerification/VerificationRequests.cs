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
	string RpName,
	string UserName,
	string DisplayHint,
	IReadOnlyList<DatabaseInfo> Databases,
	IReadOnlyList<EntryMatchInfo> CandidateEntries,
	bool EnterpriseAttestationRequested);

/// <summary>What a verifier needs to confirm a sign-in ceremony.</summary>
/// <param name="RequestPtr">The platform's WEBAUTHN_PLUGIN_OPERATION_REQUEST, for the owner window.</param>
/// <param name="EntryTitle">From KeePass, unlike UserName/DisplayHint which come from the Windows cache.</param>
internal sealed record SignInVerification(
	nint RequestPtr,
	Guid TransactionId,
	string RpId,
	string UserName,
	string DisplayHint,
	string? EntryTitle = null,
	string? DatabaseName = null,
	string? Icon = null);
