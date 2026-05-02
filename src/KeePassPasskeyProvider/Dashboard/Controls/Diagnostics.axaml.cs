using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;
using KeePassPasskeyProvider.Dashboard.ViewModel;

namespace KeePassPasskeyProvider.Dashboard.Controls;

public partial class Diagnostics : UserControl
{
    private DiagnosticsViewModel? _vm;

    public Diagnostics()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_vm != null)
            _vm.PropertyChanged -= OnViewModelPropertyChanged;
        _vm = DataContext as DiagnosticsViewModel;
        if (_vm != null)
            _vm.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DiagnosticsViewModel.LogText) && string.IsNullOrEmpty(LogTextBlock.SelectedText))
            LogScrollViewer.ScrollToEnd();
        else if (e.PropertyName == nameof(DiagnosticsViewModel.PluginLogText) && string.IsNullOrEmpty(PluginLogTextBlock.SelectedText))
            PluginLogScrollViewer.ScrollToEnd();
    }

    private void LogTextBlock_GotFocus(object sender, GotFocusEventArgs e)
    {
        var offset = LogScrollViewer.Offset;
        Dispatcher.UIThread.Post(() =>
            LogScrollViewer.Offset = offset,
            DispatcherPriority.Loaded);
    }

    private void PluginLogTextBlock_GotFocus(object sender, GotFocusEventArgs e)
    {
        var offset = PluginLogScrollViewer.Offset;
        Dispatcher.UIThread.Post(() =>
            PluginLogScrollViewer.Offset = offset,
            DispatcherPriority.Loaded);
    }
}
