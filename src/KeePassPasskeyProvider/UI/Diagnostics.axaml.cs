using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;

namespace KeePassPasskeyProvider.UI;

public partial class Diagnostics : UserControl
{
    private MainWindowViewModel? _vm;

    public Diagnostics()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_vm != null)
            _vm.PropertyChanged -= OnViewModelPropertyChanged;
        _vm = DataContext as MainWindowViewModel;
        if (_vm != null)
            _vm.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.LogText) && string.IsNullOrEmpty(LogTextBlock.SelectedText))
            LogScrollViewer.ScrollToEnd();
    }

    private void LogTextBlock_GotFocus(object sender, GotFocusEventArgs e)
    {
        var offset = LogScrollViewer.Offset;
        Dispatcher.UIThread.Post(() =>
            LogScrollViewer.Offset = offset,
            DispatcherPriority.Loaded);
    }
}
