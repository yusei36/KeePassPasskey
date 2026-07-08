// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Styling;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Settings;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.ViewModel;

public sealed partial class SettingsViewModel : ObservableObject
{
    [ObservableProperty] private UserVerificationMode _registrationVerification;
    [ObservableProperty] private UserVerificationMode _signInVerification;
    [ObservableProperty] private bool _showErrorNotifications;
    [ObservableProperty] private bool _addPasskeyTag;
    [ObservableProperty] private bool _saveToExistingEntry;
    [ObservableProperty] private string _entryTitleTemplate = "";
    [ObservableProperty] private bool _resolveTitlePlaceholders;
    [ObservableProperty] private PasskeyEntryGroupMode _newEntryGroupMode;
    [ObservableProperty] private double _notificationTimeoutSeconds;
    [ObservableProperty] private LogLevel _logLevel;
    [ObservableProperty] private bool _syncCredentialsToWindows;
    [ObservableProperty] private double _statusRefreshIntervalSeconds;
    [ObservableProperty] private bool _newPasskeyBackupEligible;
    [ObservableProperty] private bool _newPasskeyBackupState;

    // BS implies BE: turning eligibility off forces synced off.
    partial void OnNewPasskeyBackupEligibleChanged(bool value)
    {
        if (!value) NewPasskeyBackupState = false;
    }
    private Theme _theme = AppSettings.Current.Theme;
    public Theme Theme
    {
        get => _theme;
        set
        {
            if (!SetProperty(ref _theme, value)) return;
            AppSettings.Current.Theme = value;
            AppSettings.Save(AppSettings.Current);
            ApplyTheme(value);
        }
    }

    private bool _enableTrayIcon = AppSettings.Current.EnableTrayIcon;
    public bool EnableTrayIcon
    {
        get => _enableTrayIcon;
        set
        {
            if (!SetProperty(ref _enableTrayIcon, value)) return;
            AppSettings.Current.EnableTrayIcon = value;
            AppSettings.Save(AppSettings.Current);
            TrayStateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    internal static async Task SetTrayStartupTaskAsync(bool enable)
    {
        try
        {
            var task = await Windows.ApplicationModel.StartupTask.GetAsync(
                KeePassPasskeyProvider.Authenticator.PluginConstants.StartupTaskTrayApp);
            if (enable)
                await task.RequestEnableAsync();
            else
                task.Disable();
        }
        catch (Exception ex)
        {
            Log.Warn($"Could not update tray startup task: {ex.Message}");
        }
    }

    internal event EventHandler? TrayStateChanged;

    internal void ReloadTrayIconState() =>
        SetProperty(ref _enableTrayIcon, AppSettings.Current.EnableTrayIcon, nameof(EnableTrayIcon));

    [ObservableProperty] private bool _hasNonDefaultSettings;
    [ObservableProperty] private bool _canResetToDefaults;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanSave))] private bool _isSaving;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CanSave))] private bool _hasUnsavedChanges;
    public bool CanSave => HasUnsavedChanges && !IsSaving;

    private static readonly KeePassPasskeySettings DefaultSettings = new();
    private bool _isLoading;

    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_isLoading && e.PropertyName is not (nameof(IsSaving) or nameof(HasUnsavedChanges) or nameof(EnableTrayIcon) or nameof(Theme)))
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
        AddPasskeyTag                          = AddPasskeyTag,
        SaveToExistingEntry                    = SaveToExistingEntry,
        EntryTitleTemplate                     = EntryTitleTemplate,
        ResolveTitlePlaceholders               = ResolveTitlePlaceholders,
        NewEntryGroupMode                      = NewEntryGroupMode,
        NotificationVerificationTimeoutMilliseconds = (int)NotificationTimeoutSeconds * 1000,
        LogLevel                               = LogLevel,
        IsCredentialSyncEnabled                = SyncCredentialsToWindows,
        StatusRefreshIntervalMilliseconds      = (int)StatusRefreshIntervalSeconds * 1000,
        NewPasskeyBackupEligible               = NewPasskeyBackupEligible,
        NewPasskeyBackupState                  = NewPasskeyBackupState && NewPasskeyBackupEligible, // BS implies BE
    };

    public static UserVerificationMode[] VerificationModes { get; } = (UserVerificationMode[])Enum.GetValues(typeof(UserVerificationMode));
    public static PasskeyEntryGroupMode[] GroupModes { get; } = (PasskeyEntryGroupMode[])Enum.GetValues(typeof(PasskeyEntryGroupMode));
    public static LogLevel[] LogLevels { get; } = (LogLevel[])Enum.GetValues(typeof(LogLevel));
    public static Theme[] Themes { get; } = (Theme[])Enum.GetValues(typeof(Theme));
    public string AppVersion => DiagnosticsViewModel.ClientVersionShort;
    public string AppVersionFull => DiagnosticsViewModel.ClientVersion;
    public static bool IsOfficialRelease { get; } = CheckIsOfficialRelease();

    [ObservableProperty] private string _verifyReleaseMessage = "Release build";
    private static readonly string[] Principles =["Its'y ywzxy. Ajwnkd.", "Xjqk-hzxyid.", "Dtzw ufxxpjdx. Dtzw fhhtzsyx.", "Sty dtzw ufxxpjdx, sty dtzw fhhtzsyx.", "Xtajwjnls. Fqbfdx. Dtzwx."];
    private int _verifyReleaseIndex = -1;

    [RelayCommand]
    private void VerifyRelease()
    {
        _verifyReleaseIndex = (_verifyReleaseIndex + 1) % Principles.Length;
        VerifyReleaseMessage = VerifyRelease(Principles[_verifyReleaseIndex]);
    }

    private static string VerifyRelease(string text)
    {
        char[] result = new char[text.Length];
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (char.IsLetter(c))
            {
                char base_ = char.IsUpper(c) ? 'A' : 'a';
                result[i] = (char)((c - base_ + 21) % 26 + base_);
            }
            else
            {
                result[i] = c;
            }
        }
        return new string(result);
    }

    private static bool CheckIsOfficialRelease()
    {
        var version = DiagnosticsViewModel.ClientVersion;
        if (version.Contains('-'))
            return false;
        try
        {
            return Authenticator.PluginConstants.IsOfficialPackageFamilyName(
                Windows.ApplicationModel.Package.Current.Id.FamilyName);
        }
        catch
        {
            return false;
        }
    }

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
        await Application.CopyToClipboardAsync(text);
    }

    // Log level takes effect immediately without a full KeePass save.
    // Current is cloned rather than mutated so Current.LogLevel stays at the last
    // KeePass-synced value, keeping the Save button enabled and allowing Reset to revert.
    // Until saved or reset, Log.MinLevel intentionally differs from Current.LogLevel.
    partial void OnLogLevelChanged(LogLevel value)
    {
        if (_isLoading) return;
        var toCache = KeePassPasskeySettings.Current.Clone();
        toCache.LogLevel = value;
        SettingsCache.Save(toCache);
    }

    internal static void ApplyTheme(Theme theme) =>
        Application.Current!.RequestedThemeVariant = theme switch
        {
            Theme.Light => ThemeVariant.Light,
            Theme.Dark  => ThemeVariant.Dark,
            _           => ThemeVariant.Default,
        };

    [RelayCommand]
    private void Reset()
    {
        LoadFromCurrent();
        SettingsCache.Save(KeePassPasskeySettings.Current);
    }

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
        AddPasskeyTag                   = c.AddPasskeyTag;
        SaveToExistingEntry             = c.SaveToExistingEntry;
        EntryTitleTemplate              = c.EntryTitleTemplate;
        ResolveTitlePlaceholders        = c.ResolveTitlePlaceholders;
        NewEntryGroupMode               = c.NewEntryGroupMode;
        NotificationTimeoutSeconds      = c.NotificationVerificationTimeoutMilliseconds / 1000;
        LogLevel                        = c.LogLevel;
        SyncCredentialsToWindows        = c.IsCredentialSyncEnabled;
        StatusRefreshIntervalSeconds    = c.StatusRefreshIntervalMilliseconds / 1000;
        NewPasskeyBackupEligible        = c.NewPasskeyBackupEligible;
        NewPasskeyBackupState           = c.NewPasskeyBackupState && c.NewPasskeyBackupEligible;
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

            // Reflect the sync toggle in the Windows cache immediately: enabling reconciles it
            // against the open databases, disabling clears it. The app is the packaged process, so
            // it can call the WebAuthn cache APIs directly.
            var clsid = Authenticator.PluginConstants.KeePassPasskeyProviderClsid;
            await Task.Run(() =>
            {
                if (settings.IsCredentialSyncEnabled)
                    Authenticator.CredentialCache.SyncToWindowsCache(clsid);
                else
                    Authenticator.CredentialCache.ClearWindowsCache(clsid);
            });
        }
        finally
        {
            IsSaving = false;
        }
    }
}
