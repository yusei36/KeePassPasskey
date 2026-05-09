using KeePass.Plugins;
using KeePassPasskeyShared.Config;
using Newtonsoft.Json;

namespace KeePassPasskey.Config
{
    internal sealed class PluginSettings
    {
        private const string ConfigKey = "KeePassPasskey.Config";
        private readonly KeePass.App.Configuration.AceCustomConfig _customConfig;

        internal PluginSettings(IPluginHost host)
        {
            _customConfig = host.CustomConfig;
        }

        internal KeePassPasskeyConfig Load()
        {
            string json = _customConfig.GetString(ConfigKey, null);
            if (string.IsNullOrEmpty(json))
                return new KeePassPasskeyConfig();
            return JsonConvert.DeserializeObject<KeePassPasskeyConfig>(json) ?? new KeePassPasskeyConfig();
        }

        internal void Save(KeePassPasskeyConfig config)
        {
            _customConfig.SetString(ConfigKey, JsonConvert.SerializeObject(config));
        }
    }
}
