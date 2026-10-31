// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.ComponentModel;
using KeePassPasskeyShared.Passkey;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class AlgorithmPreferenceViewModel(PasskeyAlgorithm algorithm, bool enabled) : ObservableObject
{
	public PasskeyAlgorithm Algorithm { get; } = algorithm;
	[ObservableProperty] public partial bool Enabled { get; set; } = enabled;
	// False for the last enabled algorithm: switching it off would fail every registration.
	[ObservableProperty] public partial bool CanToggle { get; set; } = true;
	[ObservableProperty] public partial bool CanMoveUp { get; set; }
	[ObservableProperty] public partial bool CanMoveDown { get; set; }

	public string Name => Algorithm.ToString();

	// Neutral technical description after the IANA COSE registry, plus the key this plugin generates.
	public string Description => Algorithm switch
	{
		PasskeyAlgorithm.ES256 => "ECDSA, P-256, SHA-256 (-7)",
		PasskeyAlgorithm.EdDSA => "Ed25519 (-8)",
		PasskeyAlgorithm.RS256 => "RSA 2048, PKCS#1 v1.5, SHA-256 (-257)",
		_ => $"({(int)Algorithm})",
	};
}
