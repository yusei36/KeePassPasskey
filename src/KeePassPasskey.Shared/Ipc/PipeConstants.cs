using System.Reflection;

namespace KeePassPasskey.Shared.Ipc
{
    public static class PipeConstants
    {
        public const string PipeName = "keepass-passkey-provider";

        public static readonly string Version =
            Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "unknown";
    }
}
