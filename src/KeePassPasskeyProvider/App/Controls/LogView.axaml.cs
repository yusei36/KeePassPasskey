// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Media;
using Avalonia.Threading;
using KeePassPasskeyShared;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Controls;

public partial class LogView : UserControl
{
    private LogViewModel? _vm;

    private static IBrush? FindBrush(string key)
    {
        if (Application.Current is IResourceHost host &&
            host.TryGetResource(key, Application.Current.ActualThemeVariant, out var value))
            return value as IBrush;
        return null;
    }

    public LogView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        if (Application.Current != null)
            Application.Current.ActualThemeVariantChanged += OnThemeChanged;
    }

    private void OnThemeChanged(object? sender, EventArgs e)
    {
        if (_vm == null) return;
        UpdateLogInlines(LogTextBlock, _vm.ProviderLogLines);
        UpdateLogInlines(PluginLogTextBlock, _vm.PluginLogLines);
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_vm != null)
            _vm.PropertyChanged -= OnViewModelPropertyChanged;
        _vm = DataContext as LogViewModel;
        if (_vm != null)
        {
            _vm.PropertyChanged += OnViewModelPropertyChanged;
            UpdateLogInlines(LogTextBlock, _vm.ProviderLogLines);
            UpdateLogInlines(PluginLogTextBlock, _vm.PluginLogLines);
            Dispatcher.UIThread.Post(() =>
            {
                LogScrollViewer.ScrollToEnd();
                PluginLogScrollViewer.ScrollToEnd();
            }, DispatcherPriority.Loaded);
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(LogViewModel.ProviderLogLines)
            && string.IsNullOrEmpty(LogTextBlock.SelectedText))
        {
            UpdateLogInlines(LogTextBlock, _vm!.ProviderLogLines);
            LogScrollViewer.ScrollToEnd();
        }
        else if (e.PropertyName == nameof(LogViewModel.PluginLogLines)
            && string.IsNullOrEmpty(PluginLogTextBlock.SelectedText))
        {
            UpdateLogInlines(PluginLogTextBlock, _vm!.PluginLogLines);
            PluginLogScrollViewer.ScrollToEnd();
        }
    }

    private void UpdateLogInlines(SelectableTextBlock block, IReadOnlyList<LogLine> lines)
    {
        block.Inlines ??= new InlineCollection();
        var inlines = block.Inlines;
        inlines.Clear();
        for (int i = 0; i < lines.Count; i++)
        {
            if (i > 0) inlines.Add(new LineBreak());
            var line = lines[i];
            var run = new Run(line.Text);
            run.Foreground = line.Level switch
            {
                LogLevel.Error => FindBrush("SystemFillColorCriticalBrush"),
                LogLevel.Warn  => FindBrush("SystemFillColorCautionBrush"),
                LogLevel.Debug => FindBrush("TextFillColorTertiaryBrush"),
                _              => FindBrush("TextFillColorPrimaryBrush"),
            };
            inlines.Add(run);
        }
    }
}
