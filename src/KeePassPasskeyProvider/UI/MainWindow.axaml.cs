using Avalonia.Controls;

namespace KeePassPasskeyProvider.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainWindowViewModel();
    }
}
