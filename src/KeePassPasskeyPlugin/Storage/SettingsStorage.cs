// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskey.Storage;

internal sealed class SettingsStorage
{
	private const string ConfigKey = "KeePassPasskey.Settings";

	// Kept out of KeePassPasskeySettings on purpose: this is state, not a setting, and the settings
	// object is compared wholesale to drive the app's unsaved-changes prompt.
	private const string SkippedPluginVersionKey = "KeePassPasskey.SkippedPluginVersion";

	private readonly KeePass.App.Configuration.AceCustomConfig _customConfig;

	internal SettingsStorage(IPluginHost host)
	{
		_customConfig = host.CustomConfig;
	}

	internal KeePassPasskeySettings Load()
	{
		string json = _customConfig.GetString(ConfigKey, null);
		if (string.IsNullOrEmpty(json))
			return new KeePassPasskeySettings();
		return JsonConvert.DeserializeObject<KeePassPasskeySettings>(json) ?? new KeePassPasskeySettings();
	}

	internal void Save(KeePassPasskeySettings settings)
	{
		_customConfig.SetString(ConfigKey, JsonConvert.SerializeObject(settings));
	}

	internal string LoadSkippedPluginVersion() => _customConfig.GetString(SkippedPluginVersionKey, null);

	internal void SaveSkippedPluginVersion(string version) =>
		_customConfig.SetString(SkippedPluginVersionKey, version);
}
