using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Config
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum Theme { System, Light, Dark }
}
