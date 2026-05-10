using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum Theme { System, Light, Dark }
}
