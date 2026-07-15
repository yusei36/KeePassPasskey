// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings;

// Controls how the pre-verification excludeCredentials check is scoped. A relying party can send
// excludeCredentials to prevent a second passkey being registered for an account it already knows.
// Relaxing this lets the user keep duplicate passkeys (e.g. the same account across several
// databases) even when the website asks not to.
[JsonConverter(typeof(StringEnumConverter))]
public enum ExcludeCredentialCheckMode
{
	// Never reject on excludeCredentials; always allow a duplicate passkey.
	None = 0,

	// Only reject when the duplicate lives in the target (active) database. Default.
	TargetDatabase = 1,

	// Reject when the duplicate lives in any open database (spec-compliant scope).
	AllDatabases = 2,
}
