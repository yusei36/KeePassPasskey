using System.ComponentModel;
using System.Runtime.InteropServices;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Plugin;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.ViewModels;

internal sealed partial class MainWindowViewModel : ObservableObject
{
    public StatusHeroViewModel  StatusHero  { get; }
    public SetupGuideViewModel  SetupGuide  { get; }
    public DiagnosticsViewModel Diagnostics { get; }

    [ObservableProperty] private bool _isRefreshing;

    public bool IsNotPackaged { get; } = !IsRunningAsPackage();

    // Internal provider state
    private bool _pluginRunning;
    private bool _providerEnabled;
    private bool _isRegistered;
    private bool _autoregisterError;
    private PingStatus? _pingStatus;

    private readonly PipeClient _pipeClient = new(msg => Log.Debug(msg, nameof(PipeClient)));

    public MainWindowViewModel()
    {
        var registerCmd   = new AsyncRelayCommand(RegisterAsync);
        var unregisterCmd = new AsyncRelayCommand(UnregisterAsync);
        var refreshCmd    = new AsyncRelayCommand(RefreshAsync);

        StatusHero  = new StatusHeroViewModel(registerCmd, unregisterCmd, refreshCmd);
        SetupGuide  = new SetupGuideViewModel();
        Diagnostics = new DiagnosticsViewModel();
        SetupGuide.PropertyChanged += OnSetupGuidePropertyChanged;
        Diagnostics.PropertyChanged += OnDiagnosticsPropertyChanged;

        AutoRegisterIfNeeded();
        DoRefresh();

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        timer.Tick += (_, _) => DoRefresh();
        timer.Start();
    }

    private void AutoRegisterIfNeeded()
    {
        int stateHr = PluginRegistration.GetState(out _);
        if (stateHr >= 0) return;

        int hr = PluginRegistration.Register();
        _autoregisterError = hr < 0;
    }

    private async Task RegisterAsync()
    {
        _autoregisterError = false;
        int hr = PluginRegistration.Register();
        if (hr < 0)
        {
            _autoregisterError = true;
            await ShowPluginRegistrationErrorAsync("Register", hr);
        }
        else
        {
            DoRefresh();
        }
    }

    private async Task UnregisterAsync()
    {
        _autoregisterError = false;
        int hr = PluginRegistration.Unregister();
        if (hr < 0)
        {
            await ShowPluginRegistrationErrorAsync("Unregister", hr);
        }
        else
        {
            DoRefresh();
        }
    }

    private async Task RefreshAsync()
    {
        IsRefreshing = true;
        RefreshProviderStatus();
        ApplyPingResponse(await Task.Run(() => _pipeClient.Ping()));
        IsRefreshing = false;
    }

    private void DoRefresh()
    {
        RefreshProviderStatus();
        ApplyPingResponse(_pipeClient.Ping());
    }

    private void RefreshProviderStatus()
    {
        int hr = PluginRegistration.GetState(out var state);
        _isRegistered    = hr >= 0;
        _providerEnabled = hr >= 0 && state == AuthenticatorState.AuthenticatorState_Enabled;
        UpdateChildren();
    }

    private void ApplyPingResponse(PingResponse? pingResponse)
    {
        _pingStatus    = pingResponse?.Status;
        _pluginRunning = _pingStatus == PingStatus.Ready;

        Diagnostics.ServerVersion = pingResponse?.Version;
        Diagnostics.PingStatus    = pingResponse?.Status;
        UpdateChildren();

        Log.Info($"status: {_pingStatus?.ToString() ?? "no response"}, clientVersion: {PipeConstants.Version}, serverVersion: {pingResponse?.Version}");
    }

    private void UpdateChildren()
    {
        StatusHero.Update(_pluginRunning, _providerEnabled, _isRegistered, _autoregisterError, _pingStatus);
        SetupGuide.IsReady = _pluginRunning && _providerEnabled;
    }

    private void OnSetupGuidePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SetupGuideViewModel.IsSetupExpanded) && SetupGuide.IsSetupExpanded)
            Diagnostics.IsLogVisible = false;
    }

    private void OnDiagnosticsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DiagnosticsViewModel.IsLogVisible) && Diagnostics.IsLogVisible)
            SetupGuide.IsSetupExpanded = false;
    }

    private static Task ShowPluginRegistrationErrorAsync(string operation, int hr)
    {
        string title = $"{operation} failed";
        string message =
            $"Windows returned HRESULT 0x{hr:X8} while trying to {operation.ToLowerInvariant()} the passkey provider.";
        return DialogService.ShowErrorAsync(title, message);
    }

    private static bool IsRunningAsPackage()
    {
        const int APPMODEL_ERROR_NO_PACKAGE = 15700;
        uint length = 0;
        int rc = GetCurrentPackageFullName(ref length, null);
        return rc != APPMODEL_ERROR_NO_PACKAGE;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, char[]? packageFullName);
}
