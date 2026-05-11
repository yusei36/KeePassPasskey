// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Kögel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using FluentAvalonia.UI.Controls;
using FluentAvalonia.UI.Windowing;
using KeePassPasskeyProvider.Dashboard.Pages;
using KeePassPasskeyProvider.Dashboard.ViewModel;

namespace KeePassPasskeyProvider.Dashboard;

public partial class MainWindow : AppWindow
{
    private HomePage? _homePage;
    private DiagnosticsPage? _diagnosticsPage;
    private SettingsPage? _settingsPage;

    public MainWindow() : this(new MainWindowViewModel()) { } // required by Avalonia XAML loader

    public MainWindow(MainWindowViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
        NavView.SelectionChanged += NavView_SelectionChanged;
        NavView.TemplateApplied += (_, e) =>
        {
            if (e.NameScope.Find<Grid>("ItemsContainerGrid") is { } grid)
                grid.Margin = new Avalonia.Thickness(0);
        };
    }

    protected override void OnApplyTemplate(TemplateAppliedEventArgs e)
    {
        base.OnApplyTemplate(e);
        if (e.NameScope.Find<Image>("Icon") is { } icon)
        {
            icon.Width = 20;
            icon.Height = 20;
            icon.Margin = new Avalonia.Thickness(12, 0, 0, 0);
        }
        if (e.NameScope.Find<TextBlock>("TitleText") is { } title)
        {
            title.Margin = new Avalonia.Thickness(36, 0, 0, 0);
        }
    }

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);
        NavView.SelectedItem = NavView.MenuItems.OfType<NavigationViewItem>().First();
    }

    private void NavView_SelectionChanged(object? sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item) return;
        var vm = (MainWindowViewModel)DataContext!;
        switch (item.Tag?.ToString())
        {
            case "home":
                _homePage ??= new HomePage { DataContext = vm };
                NavView.Content = _homePage;
                break;
            case "diagnostics":
                vm.Diagnostics.IsLogVisible = true;
                _diagnosticsPage ??= new DiagnosticsPage { DataContext = vm.Diagnostics };
                NavView.Content = _diagnosticsPage;
                break;
            case "settings":
                _settingsPage ??= new SettingsPage(vm.Settings);
                _ = vm.Settings.SyncFromKeePassAsync();
                NavView.Content = _settingsPage;
                break;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.IsRefreshing) && sender is MainWindowViewModel vm)
            Cursor = vm.IsRefreshing ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
    }
}
