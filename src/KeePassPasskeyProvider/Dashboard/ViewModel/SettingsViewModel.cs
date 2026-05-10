using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Config;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.Dashboard.Utils;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Dashboard.ViewModel;

public sealed partial class SettingsViewModel : ObservableObject
{
    [ObservableProperty] private UserVerificationMode _registrationVerification;
    [ObservableProperty] private UserVerificationMode _signInVerification;
    [ObservableProperty] private bool _showErrorNotifications;
    [ObservableProperty] private double _notificationTimeoutSeconds;
    [ObservableProperty] private LogLevel _logLevel;
    [ObservableProperty] private double _credentialSyncIntervalSeconds;
    [ObservableProperty] private double _statusRefreshIntervalSeconds;
    [ObservableProperty] private double _configSyncIntervalSeconds;
    [ObservableProperty] private double _credentialSyncShutdownThreshold;
    [ObservableProperty] private bool _isSaving;

    public static UserVerificationMode[] VerificationModes { get; } = (UserVerificationMode[])Enum.GetValues(typeof(UserVerificationMode));
    public static LogLevel[] LogLevels { get; } = (LogLevel[])Enum.GetValues(typeof(LogLevel));

    public SettingsViewModel() => LoadFromCurrent();

    private void LoadFromCurrent()
    {
        var c = KeePassPasskeyConfig.Current;
        RegistrationVerification       = c.RegistrationVerification;
        SignInVerification              = c.SignInVerification;
        ShowErrorNotifications         = c.ShowErrorNotifications;
        NotificationTimeoutSeconds     = c.NotificationVerificationTimeoutMilliseconds / 1000;
        LogLevel                       = c.LogLevel;
        CredentialSyncIntervalSeconds  = c.CredentialSyncIntervalMilliseconds / 1000;
        StatusRefreshIntervalSeconds   = c.StatusRefreshIntervalMilliseconds / 1000;
        ConfigSyncIntervalSeconds      = c.ConfigSyncIntervalMilliseconds / 1000;
        CredentialSyncShutdownThreshold = c.CredentialSyncShutdownThreshold;
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        IsSaving = true;
        try
        {
            var config = new KeePassPasskeyConfig
            {
                RegistrationVerification               = RegistrationVerification,
                SignInVerification                     = SignInVerification,
                ShowErrorNotifications                 = ShowErrorNotifications,
                NotificationVerificationTimeoutMilliseconds = (int)NotificationTimeoutSeconds * 1000,
                LogLevel                               = LogLevel,
                CredentialSyncIntervalMilliseconds     = (int)CredentialSyncIntervalSeconds * 1000,
                StatusRefreshIntervalMilliseconds      = (int)StatusRefreshIntervalSeconds * 1000,
                ConfigSyncIntervalMilliseconds         = (int)ConfigSyncIntervalSeconds * 1000,
                CredentialSyncShutdownThreshold        = (int)CredentialSyncShutdownThreshold,
            };

            var response = await Task.Run(() =>
                new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)))
                    .SetConfig(new SetConfigRequest { Config = config }));

            if (response == null || response.ErrorCode != null)
            {
                string detail = response?.ErrorMessage ?? "KeePass is not running. Start KeePass with the passkey plugin before saving settings.";
                await DialogService.ShowErrorAsync("Could not save settings", detail);
                return;
            }

            KeePassPasskeyConfig.Current = config;
            ConfigPersistence.Save(config);
        }
        finally
        {
            IsSaving = false;
        }
    }
}
