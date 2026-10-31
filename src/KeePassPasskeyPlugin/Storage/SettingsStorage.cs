// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Xml;
using KeePass.App.Configuration;
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

	private readonly AceCustomConfig _customConfig;

	// KeePass merges this into the custom config at startup, but a save in this session would
	// overwrite it there, so the enforced value is kept and read from here instead.
	private readonly string _enforcedJson;

	internal SettingsStorage(IPluginHost host)
	{
		_customConfig = host.CustomConfig;
		_enforcedJson = FindEnforcedValue(AppConfigSerializer.EnforcedConfigXml, ConfigKey);
	}

	/// <summary>KeePass.config.enforced.xml sets the settings: saves are stored but have no effect.</summary>
	internal bool IsEnforced => _enforcedJson != null;

	internal KeePassPasskeySettings Load()
	{
		if (_enforcedJson != null)
			return ParseEnforced(_enforcedJson);

		string json = _customConfig.GetString(ConfigKey, null);
		if (string.IsNullOrEmpty(json))
			return new KeePassPasskeySettings();
		return JsonConvert.DeserializeObject<KeePassPasskeySettings>(json) ?? new KeePassPasskeySettings();
	}

	// A managed install disallows AAGUID spoofing unless the enforced JSON allows it explicitly.
	internal static KeePassPasskeySettings ParseEnforced(string json)
	{
		var settings = new KeePassPasskeySettings { AllowAaguidSpoofing = false };
		if (!string.IsNullOrEmpty(json))
			JsonConvert.PopulateObject(json, settings);
		return settings;
	}

	internal void Save(KeePassPasskeySettings settings)
	{
		_customConfig.SetString(ConfigKey, JsonConvert.SerializeObject(settings));
	}

	internal string LoadSkippedPluginVersion() => _customConfig.GetString(SkippedPluginVersionKey, null);

	internal void SaveSkippedPluginVersion(string version) =>
		_customConfig.SetString(SkippedPluginVersionKey, version);

	internal static string FindEnforcedValue(XmlDocument enforced, string key)
	{
		XmlNodeList items = enforced?.SelectNodes("/Configuration/Custom/Item");
		if (items == null) return null;

		foreach (XmlNode item in items)
		{
			if (item["Key"]?.InnerText != key) continue;
			// Removes the user's item rather than setting one.
			if (item.Attributes?["MergeNodeMode"]?.Value == "Remove") return null;
			return item["Value"]?.InnerText;
		}
		return null;
	}
}
