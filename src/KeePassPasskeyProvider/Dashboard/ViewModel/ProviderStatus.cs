namespace KeePassPasskeyProvider.Dashboard.ViewModel;

public enum ProviderStatus
{
    NotRegistered,
    AutoregisterFailed,
    WaitingToBeEnabled,
    PluginNotRunning,
    NoDatabase,
    VersionMismatch,
    Ready,
}
