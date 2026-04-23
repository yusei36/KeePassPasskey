namespace KeePassPasskeyProvider.ViewModels;

internal enum ProviderStatus
{
    NotRegistered,
    AutoregisterFailed,
    WaitingToBeEnabled,
    PluginNotRunning,
    NoDatabase,
    VersionMismatch,
    Ready,
}
