using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Input;
using Avalonia.Media;
using Avalonia.Threading;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Plugin;

namespace KeePassPasskeyProvider.UI;

internal sealed class MainWindowViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _statusText = "Checking...";
    private string _resultMessage = "";
    private IBrush _statusColor = Brushes.Gray;

    public string StatusText
    {
        get => _statusText;
        private set { _statusText = value; OnPropertyChanged(); }
    }

    public string ResultMessage
    {
        get => _resultMessage;
        private set { _resultMessage = value; OnPropertyChanged(); }
    }

    public IBrush StatusColor
    {
        get => _statusColor;
        private set { _statusColor = value; OnPropertyChanged(); }
    }

    public bool IsNotPackaged { get; } = !IsRunningAsPackage();

    public ICommand RegisterCommand          { get; }
    public ICommand UnregisterCommand        { get; }
    public ICommand RefreshCommand           { get; }
    public ICommand OpenPasskeySettingsCommand { get; }

    public MainWindowViewModel()
    {
        RegisterCommand            = new RelayCommand(DoRegister);
        UnregisterCommand          = new RelayCommand(DoUnregister);
        RefreshCommand             = new RelayCommand(DoManualRefresh);
        OpenPasskeySettingsCommand = new RelayCommand(DoOpenPasskeySettings);
        DoRefresh();

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        timer.Tick += (_, _) => DoRefresh();
        timer.Start();
    }

    private void DoRegister()
    {
        int hr = PluginRegistration.Register();
        ResultMessage = hr >= 0
            ? "Registered successfully."
            : $"Registration failed: 0x{hr:X8}";
        DoRefresh();
    }

    private void DoUnregister()
    {
        int hr = PluginRegistration.Unregister();
        ResultMessage = hr >= 0
            ? "Unregistered successfully."
            : $"Unregister failed: 0x{hr:X8}";
        DoRefresh();
    }

    private static void DoOpenPasskeySettings()
    {
        Process.Start(new ProcessStartInfo("ms-settings:savedpasskeys") { UseShellExecute = true });
    }

    private void DoManualRefresh()
    {
        ResultMessage = "";
        DoRefresh();
    }

    private void DoRefresh()
    {
        int hr = PluginRegistration.GetState(out var state);
        if (hr >= 0)
        {
            bool enabled = state == AuthenticatorState.AuthenticatorState_Enabled;
            StatusText  = enabled ? "Enabled" : "Disabled";
            StatusColor = enabled ? Brushes.Green : Brushes.OrangeRed;
        }
        else
        {
            StatusText  = $"Unknown or not registered (0x{hr:X8})";
            StatusColor = Brushes.Gray;
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private static bool IsRunningAsPackage()
    {
        const int APPMODEL_ERROR_NO_PACKAGE  = 15700;
        uint length = 0;
        int rc = GetCurrentPackageFullName(ref length, null);
        return rc != APPMODEL_ERROR_NO_PACKAGE;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, char[]? packageFullName);
}

internal sealed class RelayCommand(Action execute) : ICommand
{
#pragma warning disable CS0067 // currently not used, pragma needs to be removed once it is used
    public event EventHandler? CanExecuteChanged;
#pragma warning restore CS0067
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => execute();
}
