// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Generic;
using KeePassPasskey.Passkey;
using KeePassPasskey.Storage;
using KeePassPasskeyShared.Passkey;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class AlgorithmSelectorTests
{
	private const int ES256 = (int)PasskeyAlgorithm.ES256;
	private const int EdDSA = (int)PasskeyAlgorithm.EdDSA;
	private const int RS256 = (int)PasskeyAlgorithm.RS256;
	private const int ES384 = -35;

	private static List<AlgorithmPreference> Defaults => AlgorithmPreference.CreateDefaults();

	private static List<AlgorithmPreference> Prefs(params (PasskeyAlgorithm alg, bool enabled)[] items)
	{
		var list = new List<AlgorithmPreference>();
		foreach (var (alg, enabled) in items) list.Add(new AlgorithmPreference(alg, enabled));
		return list;
	}

	[Fact]
	public void PreferenceOrder_Default_IgnoresWebsiteOrder()
	{
		Assert.Equal(PasskeyAlgorithm.ES256,
			AlgorithmSelector.Select(new[] { EdDSA, RS256, ES256 }, AlgorithmSelectionMode.PreferenceOrder, Defaults));
	}

	[Fact]
	public void RelyingPartyOrder_TakesFirstRequestedSupported()
	{
		Assert.Equal(PasskeyAlgorithm.EdDSA,
			AlgorithmSelector.Select(new[] { ES384, EdDSA, RS256, ES256 }, AlgorithmSelectionMode.RelyingPartyOrder, Defaults));
	}

	[Fact]
	public void PreferenceOrder_FollowsCustomOrder()
	{
		var prefs = Prefs((PasskeyAlgorithm.EdDSA, true), (PasskeyAlgorithm.ES256, true), (PasskeyAlgorithm.RS256, true));
		Assert.Equal(PasskeyAlgorithm.EdDSA,
			AlgorithmSelector.Select(new[] { ES256, EdDSA }, AlgorithmSelectionMode.PreferenceOrder, prefs));
		Assert.Equal(PasskeyAlgorithm.ES256,
			AlgorithmSelector.Select(new[] { RS256, ES256 }, AlgorithmSelectionMode.PreferenceOrder, prefs));
	}

	[Theory]
	[InlineData(AlgorithmSelectionMode.PreferenceOrder)]
	[InlineData(AlgorithmSelectionMode.RelyingPartyOrder)]
	public void DisabledAlgorithm_IsNeverChosen(AlgorithmSelectionMode mode)
	{
		var prefs = Prefs((PasskeyAlgorithm.ES256, false), (PasskeyAlgorithm.EdDSA, true), (PasskeyAlgorithm.RS256, true));
		Assert.Equal(PasskeyAlgorithm.RS256, AlgorithmSelector.Select(new[] { ES256, RS256 }, mode, prefs));
	}

	[Fact]
	public void OnlyDisabledRequested_ReturnsNull()
	{
		var edDsaOnly = Prefs((PasskeyAlgorithm.ES256, false), (PasskeyAlgorithm.EdDSA, true), (PasskeyAlgorithm.RS256, false));
		Assert.Null(AlgorithmSelector.Select(new[] { ES256, RS256 }, AlgorithmSelectionMode.PreferenceOrder, edDsaOnly));
	}

	[Fact]
	public void NothingSupportedRequested_ReturnsNull()
	{
		Assert.Null(AlgorithmSelector.Select(new[] { ES384 }, AlgorithmSelectionMode.RelyingPartyOrder, Defaults));
	}

	[Fact]
	public void EmptyRequest_UsesWebAuthnDefaults()
	{
		Assert.Equal(PasskeyAlgorithm.ES256, AlgorithmSelector.Select(null!, AlgorithmSelectionMode.PreferenceOrder, Defaults));
		var noEs256 = Prefs((PasskeyAlgorithm.ES256, false), (PasskeyAlgorithm.EdDSA, true), (PasskeyAlgorithm.RS256, true));
		Assert.Equal(PasskeyAlgorithm.RS256, AlgorithmSelector.Select(new int[0], AlgorithmSelectionMode.PreferenceOrder, noEs256));
	}

	[Fact]
	public void Normalize_RepairsStoredList()
	{
		var stored = Prefs((PasskeyAlgorithm.RS256, false), (PasskeyAlgorithm.RS256, true), ((PasskeyAlgorithm)ES384, true), (PasskeyAlgorithm.EdDSA, true));
		var result = AlgorithmPreference.Normalize(stored);
		Assert.Equal(new[] { PasskeyAlgorithm.RS256, PasskeyAlgorithm.EdDSA, PasskeyAlgorithm.ES256 }, result.ConvertAll(p => p.Algorithm));
		Assert.Equal(new[] { false, true, true }, result.ConvertAll(p => p.Enabled));
	}

	[Fact]
	public void Normalize_AllDisabled_FallsBackToDefaults()
	{
		var stored = Prefs((PasskeyAlgorithm.EdDSA, false), (PasskeyAlgorithm.ES256, false), (PasskeyAlgorithm.RS256, false));
		var result = AlgorithmPreference.Normalize(stored);
		Assert.Equal(AlgorithmPreference.DefaultOrder, result.ConvertAll(p => p.Algorithm));
		Assert.All(result, p => Assert.True(p.Enabled));
	}

	private const string EdDsaFirstJson =
		"{\"algorithmPreferences\":[{\"algorithm\":\"EdDSA\",\"enabled\":true},{\"algorithm\":\"ES256\",\"enabled\":false}]}";

	// The list must replace the initialized defaults, not be appended to them.
	[Fact]
	public void Settings_StoredListReplacesDefaults()
	{
		var settings = JsonConvert.DeserializeObject<KeePassPasskeySettings>(EdDsaFirstJson)!;
		Assert.Equal(new[] { PasskeyAlgorithm.EdDSA, PasskeyAlgorithm.ES256 }, settings.AlgorithmPreferences.ConvertAll(p => p.Algorithm));
		Assert.Equal(2, settings.Clone().AlgorithmPreferences.Count);
	}

	[Fact]
	public void Settings_EnforcedListReplacesDefaults()
	{
		var settings = SettingsStorage.ParseEnforced(EdDsaFirstJson);
		Assert.Equal(new[] { PasskeyAlgorithm.EdDSA, PasskeyAlgorithm.ES256 }, settings.AlgorithmPreferences.ConvertAll(p => p.Algorithm));
	}

	[Fact]
	public void Settings_DefaultsRoundTrip()
	{
		var settings = new KeePassPasskeySettings();
		Assert.Equal(settings, settings.Clone());
		Assert.Equal(AlgorithmSelectionMode.PreferenceOrder, settings.AlgorithmSelectionMode);
		Assert.Equal(AlgorithmPreference.DefaultOrder, settings.AlgorithmPreferences.ConvertAll(p => p.Algorithm));
	}
}
