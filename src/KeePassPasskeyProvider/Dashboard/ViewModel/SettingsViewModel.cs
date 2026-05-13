// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
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
    [ObservableProperty] private double _credentialSyncShutdownThreshold;
    [ObservableProperty] private bool _isSaving;
    [ObservableProperty] private Theme _theme = Theme.System;
    [ObservableProperty] private bool _hasUnsavedChanges;
    [ObservableProperty] private bool _hasNonDefaultSettings;
    [ObservableProperty] private bool _canResetToDefaults;

    private static readonly KeePassPasskeySettings DefaultSettings = new();
    private bool _isLoading;

    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_isLoading && e.PropertyName is not (nameof(IsSaving) or nameof(HasUnsavedChanges)))
            CheckForUnsavedChanges();
    }

    private void CheckForUnsavedChanges()
    {
        var current = BuildSettings();
        HasUnsavedChanges     = !current.Equals(KeePassPasskeySettings.Current);
        HasNonDefaultSettings = !current.Equals(DefaultSettings);
        CanResetToDefaults    = HasNonDefaultSettings && !KeePassPasskeySettings.Current.Equals(DefaultSettings);
    }

    private KeePassPasskeySettings BuildSettings() => new()
    {
        RegistrationVerification               = RegistrationVerification,
        SignInVerification                     = SignInVerification,
        ShowErrorNotifications                 = ShowErrorNotifications,
        NotificationVerificationTimeoutMilliseconds = (int)NotificationTimeoutSeconds * 1000,
        LogLevel                               = LogLevel,
        CredentialSyncIntervalMilliseconds     = (int)CredentialSyncIntervalSeconds * 1000,
        StatusRefreshIntervalMilliseconds      = (int)StatusRefreshIntervalSeconds * 1000,
        CredentialSyncShutdownThreshold        = (int)CredentialSyncShutdownThreshold,
        Theme                                  = Theme,
    };

    public static UserVerificationMode[] VerificationModes { get; } = (UserVerificationMode[])Enum.GetValues(typeof(UserVerificationMode));
    public static LogLevel[] LogLevels { get; } = (LogLevel[])Enum.GetValues(typeof(LogLevel));
    public static Theme[] Themes { get; } = (Theme[])Enum.GetValues(typeof(Theme));

    public string AppVersion => DiagnosticsViewModel.ClientVersionShort;
    public string AppVersionFull => DiagnosticsViewModel.ClientVersion;

    private static readonly string LicensePath =
        Path.Combine(AppContext.BaseDirectory, "Resources", "LICENSE.txt");
    private static readonly string ThirdPartyNoticesPath =
        Path.Combine(AppContext.BaseDirectory, "Resources", "THIRD_PARTY_NOTICES.txt");

    public bool HasLicense           { get; } = File.Exists(LicensePath);
    public bool HasThirdPartyNotices { get; } = File.Exists(ThirdPartyNoticesPath);

    [RelayCommand]
    private void OpenUrl(string url) =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName        = url,
            UseShellExecute = true,
        });

    [RelayCommand]
    private void OpenLicense() =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName        = LicensePath,
            UseShellExecute = true,
        });

    [RelayCommand]
    private void OpenThirdPartyNotices() =>
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName        = ThirdPartyNoticesPath,
            UseShellExecute = true,
        });

    [RelayCommand]
    private async Task CopyToClipboard(string? text)
    {
        if (text is null) return;
        if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime { MainWindow: { } win })
            await (TopLevel.GetTopLevel(win)?.Clipboard?.SetTextAsync(text) ?? Task.CompletedTask);
    }

    partial void OnThemeChanged(Theme value) => ApplyTheme(value);

    internal static void ApplyTheme(Theme theme) =>
        Application.Current!.RequestedThemeVariant = theme switch
        {
            Theme.Light => ThemeVariant.Light,
            Theme.Dark  => ThemeVariant.Dark,
            _           => ThemeVariant.Default,
        };

    [RelayCommand]
    private void Reset() => LoadFromCurrent();

    [RelayCommand]
    private void ResetToDefaults() => LoadFrom(new KeePassPasskeySettings());

    internal void ReloadFromCurrent() => LoadFromCurrent();

    internal async Task SyncFromKeePassAsync()
    {
        var response = await Task.Run(() =>
            new PipeClient(msg => Log.Debug(msg, nameof(PipeClient))).GetSettings());

        if (response == null || response.ErrorCode != null) return;

        if (!response.Settings.Equals(KeePassPasskeySettings.Current))
        {
            KeePassPasskeySettings.Current = response.Settings;
            SettingsCache.Save(response.Settings);
        }
        LoadFromCurrent();
    }

    public SettingsViewModel() => LoadFromCurrent();

    private void LoadFromCurrent() => LoadFrom(KeePassPasskeySettings.Current);

    private void LoadFrom(KeePassPasskeySettings c)
    {
        _isLoading = true;
        RegistrationVerification        = c.RegistrationVerification;
        SignInVerification               = c.SignInVerification;
        ShowErrorNotifications          = c.ShowErrorNotifications;
        NotificationTimeoutSeconds      = c.NotificationVerificationTimeoutMilliseconds / 1000;
        LogLevel                        = c.LogLevel;
        CredentialSyncIntervalSeconds   = c.CredentialSyncIntervalMilliseconds / 1000;
        StatusRefreshIntervalSeconds    = c.StatusRefreshIntervalMilliseconds / 1000;
        CredentialSyncShutdownThreshold = c.CredentialSyncShutdownThreshold;
        Theme                           = c.Theme;
        _isLoading = false;
        CheckForUnsavedChanges();
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        IsSaving = true;
        try
        {
            var settings = BuildSettings();

            var response = await Task.Run(() =>
                new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)))
                    .SaveSettings(new SaveSettingsRequest { Settings = settings }));

            if (response == null || response.ErrorCode != null)
            {
                string detail = response?.ErrorMessage ?? "KeePass is not running. Start KeePass with the passkey plugin before saving settings.";
                await DialogService.ShowErrorAsync("Could not save settings", detail);
                return;
            }

            KeePassPasskeySettings.Current = settings;
            SettingsCache.Save(settings);
            HasUnsavedChanges = false;
        }
        finally
        {
            IsSaving = false;
        }
    }
}
