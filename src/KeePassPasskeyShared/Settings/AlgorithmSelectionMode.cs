// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings;

// Which order decides the algorithm of a new passkey when the website offers several enabled ones.
// Either way only algorithms the website lists in pubKeyCredParams are ever used.
[JsonConverter(typeof(StringEnumConverter))]
public enum AlgorithmSelectionMode
{
	// The order of KeePassPasskeySettings.AlgorithmPreferences. Default.
	PreferenceOrder = 0,

	// The website's pubKeyCredParams order (what CTAP2 specifies).
	RelyingPartyOrder = 1,
}
