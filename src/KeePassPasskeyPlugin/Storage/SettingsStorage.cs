// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePass.Plugins;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskey.Storage
{
    internal sealed class SettingsStorage
    {
        private const string ConfigKey = "KeePassPasskey.Settings";
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
    }
}
