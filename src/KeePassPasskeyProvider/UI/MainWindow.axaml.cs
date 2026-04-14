using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;
using System.ComponentModel;

namespace KeePassPasskeyProvider.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var vm = new MainWindowViewModel();
        DataContext = vm;
        vm.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.LogText) && string.IsNullOrEmpty(LogTextBlock.SelectedText))
            LogScrollViewer.ScrollToEnd();
    }

    private void LogTextBlock_GotFocus(object sender, GotFocusEventArgs e)
    {
        // Restore scroll position when clicking into LogTextBlock
        var offset = LogScrollViewer.Offset;
        Dispatcher.UIThread.Post(() =>
            LogScrollViewer.Offset = offset,
            DispatcherPriority.Loaded);
    }
}
