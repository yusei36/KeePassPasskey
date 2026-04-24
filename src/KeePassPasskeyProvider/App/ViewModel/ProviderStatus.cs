namespace KeePassPasskeyProvider.App.ViewModel;

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
