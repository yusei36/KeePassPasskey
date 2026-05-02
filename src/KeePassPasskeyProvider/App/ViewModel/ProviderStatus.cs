namespace KeePassPasskeyProvider.App.ViewModel;

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
