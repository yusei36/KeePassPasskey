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
    public static string AppVersion { get; } =
        "v" + (System.Reflection.CustomAttributeExtensions
            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(
                System.Reflection.Assembly.GetEntryAssembly()!)
            ?.InformationalVersion ?? "?");

    // Internal provider state
    private bool _pluginRunning;
    private bool _providerEnabled;
    private bool _isRegistered;
    private bool _autoregisterError;
    private PingStatus? _pingStatus;

    private readonly PipeClient _pipeClient = new(msg => Log.Debug(msg, nameof(PipeClient)));

    public MainWindowViewModel()
    {
        var registerCmd   = new RelayCommand(Register);
        var unregisterCmd = new RelayCommand(Unregister);
        var refreshCmd    = new AsyncRelayCommand(RefreshAsync);

        StatusHero  = new StatusHeroViewModel(registerCmd, unregisterCmd, refreshCmd);
        SetupGuide  = new SetupGuideViewModel();
        Diagnostics = new DiagnosticsViewModel();

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

    private void Register()
    {
        _autoregisterError = false;
        int hr = PluginRegistration.Register();
        if (hr < 0) _autoregisterError = true;
        DoRefresh();
    }

    private void Unregister()
    {
        _autoregisterError = false;
        PluginRegistration.Unregister();
        DoRefresh();
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

        Log.Info($"ApplyPingResponse: status: {_pingStatus?.ToString() ?? "no response"}, clientVersion: {PipeConstants.Version}, serverVersion: {pingResponse?.Version}");
    }

    private void UpdateChildren()
    {
        StatusHero.Update(_pluginRunning, _providerEnabled, _isRegistered, _autoregisterError, _pingStatus);
        SetupGuide.IsReady = _pluginRunning && _providerEnabled;
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
