// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Generic;
using System.Linq;
using KeePassPasskeyShared.Passkey;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskey.Passkey;

internal static class AlgorithmSelector
{
	// WebAuthn's default when a website sends an empty pubKeyCredParams.
	private static readonly int[] DefaultRequested = { (int)PasskeyAlgorithm.ES256, (int)PasskeyAlgorithm.RS256 };

	// The first enabled algorithm the website asked for, in the order the mode selects; null when none.
	internal static PasskeyAlgorithm? Select(IList<int> pubKeyCredParams, AlgorithmSelectionMode mode, IEnumerable<AlgorithmPreference> preferences)
	{
		var requested = pubKeyCredParams == null || pubKeyCredParams.Count == 0 ? DefaultRequested : pubKeyCredParams;
		var enabled = AlgorithmPreference.Normalize(preferences).Where(p => p.Enabled).Select(p => p.Algorithm).ToList();

		if (mode == AlgorithmSelectionMode.RelyingPartyOrder)
		{
			foreach (int alg in requested)
			{
				if (enabled.Contains((PasskeyAlgorithm)alg))
					return (PasskeyAlgorithm)alg;
			}
			return null;
		}

		foreach (var alg in enabled)
		{
			if (requested.Contains((int)alg))
				return alg;
		}
		return null;
	}
}
