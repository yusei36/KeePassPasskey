// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using FluentAvalonia.UI.Controls;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Pages;

public partial class SettingsPage : UserControl
{
    public SettingsPage() : this(new SettingsViewModel()) { }

    public SettingsPage(SettingsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SettingsViewModel.IsSaving) && sender is SettingsViewModel vm)
            Cursor = vm.IsSaving ? new Cursor(StandardCursorType.Wait) : Cursor.Default;
    }

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);
        this.AddHandler(GotFocusEvent, OnAnyGotFocus, RoutingStrategies.Bubble);
        this.AddHandler(KeyDownEvent, OnAnyKeyDown, RoutingStrategies.Tunnel);
    }

    protected override void OnUnloaded(RoutedEventArgs e)
    {
        base.OnUnloaded(e);
        this.RemoveHandler(GotFocusEvent, OnAnyGotFocus);
        this.RemoveHandler(KeyDownEvent, OnAnyKeyDown);
        foreach (var nb in this.GetVisualDescendants().OfType<NumberBox>())
            nb.ValueChanged -= NumberBox_ValueChanged;
    }

    private static void OnAnyGotFocus(object? sender, GotFocusEventArgs e)
    {
        if (e.Source is not TextBox tb) return;
        var nb = tb.GetVisualAncestors().OfType<NumberBox>().FirstOrDefault();
        if (nb == null) return;

        // Lazily subscribe ValueChanged so NaN is always caught, even for
        // NumberBoxes inside collapsed SettingsExpanders not present at OnLoaded.
        nb.ValueChanged -= NumberBox_ValueChanged;
        nb.ValueChanged += NumberBox_ValueChanged;

        if (nb.NumberFormatter == null) return;

        // Strip "s" so the user edits just the number.
        StripSecondsSuffix(tb);

        // Subscribe a one-shot LostFocus on the inner TextBox so it fires
        // directly on the TextBox â€” BEFORE the bubbled event reaches NumberBox
        // and triggers ValidateInput.
        void OnLostFocus(object? s, RoutedEventArgs _)
        {
            if (s is TextBox t)
            {
                StripSecondsSuffix(t);
                t.LostFocus -= OnLostFocus;
            }
        }
        tb.LostFocus += OnLostFocus;
    }

    private static void OnAnyKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        if (e.Source is not TextBox tb) return;
        var nb = tb.GetVisualAncestors().OfType<NumberBox>().FirstOrDefault();
        if (nb?.NumberFormatter == null) return;
        StripSecondsSuffix(tb);
    }

    private static void StripSecondsSuffix(TextBox tb)
    {
        if (tb.Text?.EndsWith("s", StringComparison.OrdinalIgnoreCase) == true)
            tb.Text = tb.Text[..^1];
    }

    private static void NumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs e)
    {
        if (double.IsNaN(e.NewValue))
            sender.Value = sender.Minimum;
    }
}
