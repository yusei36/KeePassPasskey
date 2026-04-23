using Avalonia.Input;
using Avalonia.Threading;
using System.ComponentModel;
using FluentAvalonia.UI.Windowing;

namespace KeePassPasskeyProvider.UI;

public partial class MainWindow : AppWindow
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

        if (e.PropertyName == nameof(MainWindowViewModel.IsRefreshing) && sender is MainWindowViewModel vm)
            Cursor = vm.IsRefreshing ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
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
