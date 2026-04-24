using System.ComponentModel;
using Avalonia.Input;
using FluentAvalonia.UI.Windowing;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App;

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
        if (e.PropertyName == nameof(MainWindowViewModel.IsRefreshing) && sender is MainWindowViewModel vm)
            Cursor = vm.IsRefreshing ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
    }
}
