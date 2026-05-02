using System.ComponentModel;
using Avalonia.Input;
using FluentAvalonia.UI.Windowing;
using KeePassPasskeyProvider.Dashboard.ViewModel;

namespace KeePassPasskeyProvider.Dashboard;

public partial class MainWindow : AppWindow
{
    public MainWindow() : this(new MainWindowViewModel()) { } // required by Avalonia XAML loader

    public MainWindow(MainWindowViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.IsRefreshing) && sender is MainWindowViewModel vm)
            Cursor = vm.IsRefreshing ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
    }
}
