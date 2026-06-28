// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using FluentAvalonia.UI.Controls;
using FluentAvalonia.UI.Windowing;
using KeePassPasskeyProvider.App.Pages;
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App;

public partial class MainWindow : FAAppWindow
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
        NavView.SelectedItem = NavView.MenuItems.OfType<FANavigationViewItem>().First();
    }

    internal void NavigateToHome()
    {
        NavView.SelectedItem = NavView.MenuItems.OfType<FANavigationViewItem>().First();
    }

    internal void NavigateToSettings()
    {
        var settings = NavView.FooterMenuItems.OfType<FANavigationViewItem>()
            .FirstOrDefault(i => i.Tag?.ToString() == "settings");
        if (settings != null)
            NavView.SelectedItem = settings;
    }

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        base.OnClosing(e);

        if (AppSettings.Current.EnableTrayIcon)
        {
            e.Cancel = true;
            Hide();
        }
    }

    private void NavView_SelectionChanged(object? sender, FANavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not FANavigationViewItem item) return;
        var vm = (MainWindowViewModel)DataContext!;
        switch (item.Tag?.ToString())
        {
            case "home":
                _homePage ??= new HomePage { DataContext = vm };
                NavView.Content = _homePage;
                break;
            case "diagnostics":
                vm.Diagnostics.LogPanel.IsLogVisible = true;
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
