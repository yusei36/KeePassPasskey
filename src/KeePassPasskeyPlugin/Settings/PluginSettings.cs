using KeePass.Plugins;
using KeePassPasskeyShared.Settings;
using Newtonsoft.Json;

namespace KeePassPasskey.Settings
{
    internal sealed class PluginSettings
    {
        private const string ConfigKey = "KeePassPasskey.Settings";
        private readonly KeePass.App.Configuration.AceCustomConfig _customConfig;

        internal PluginSettings(IPluginHost host)
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
