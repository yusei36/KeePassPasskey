using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using KeePassPasskeyProvider.Dashboard;
using KeePassPasskeyProvider.Dashboard.ViewModel;
using KeePassPasskeyProvider.Authenticator;

namespace KeePassPasskeyProvider;

public class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            bool autoRegisterSucceeded = PluginRegistration.EnsureRegistered();
            var vm = new MainWindowViewModel(autoRegisterSucceeded);
            desktop.MainWindow = new MainWindow(vm);
        }
        base.OnFrameworkInitializationCompleted();
    }
}
