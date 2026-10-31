// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Generic;
using System.Linq;
using KeePassPasskeyShared.Passkey;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings;

public sealed class AlgorithmPreference
{
	[JsonProperty("algorithm")]
	[JsonConverter(typeof(StringEnumConverter))]
	public PasskeyAlgorithm Algorithm { get; set; }

	[JsonProperty("enabled")]
	public bool Enabled { get; set; } = true;

	public AlgorithmPreference() { }

	public AlgorithmPreference(PasskeyAlgorithm algorithm, bool enabled = true)
	{
		Algorithm = algorithm;
		Enabled = enabled;
	}

	// ES256 first because CTAP2 requires every authenticator to support it; RS256 last as the weakest.
	public static IReadOnlyList<PasskeyAlgorithm> DefaultOrder { get; } =
		new[] { PasskeyAlgorithm.ES256, PasskeyAlgorithm.EdDSA, PasskeyAlgorithm.RS256 };

	public static List<AlgorithmPreference> CreateDefaults() =>
		DefaultOrder.Select(a => new AlgorithmPreference(a)).ToList();

	// Repairs a stored list: drops unknown and repeated algorithms, appends supported ones it lacks
	// (enabled, so an algorithm added in a later version is not silently off), and falls back to the
	// defaults when nothing is enabled, since that would fail every registration.
	public static List<AlgorithmPreference> Normalize(IEnumerable<AlgorithmPreference> stored)
	{
		var result = new List<AlgorithmPreference>();
		foreach (var p in stored ?? Enumerable.Empty<AlgorithmPreference>())
		{
			if (p == null || !DefaultOrder.Contains(p.Algorithm) || result.Any(r => r.Algorithm == p.Algorithm))
				continue;
			result.Add(new AlgorithmPreference(p.Algorithm, p.Enabled));
		}
		foreach (var a in DefaultOrder)
		{
			if (!result.Any(r => r.Algorithm == a))
				result.Add(new AlgorithmPreference(a));
		}
		return result.Any(r => r.Enabled) ? result : CreateDefaults();
	}
}
