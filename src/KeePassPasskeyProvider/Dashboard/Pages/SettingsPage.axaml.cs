using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using FluentAvalonia.UI.Controls;
using KeePassPasskeyProvider.Dashboard.ViewModel;

namespace KeePassPasskeyProvider.Dashboard.Pages;

public partial class SettingsPage : UserControl
{
    public SettingsPage() : this(new SettingsViewModel()) { }

    public SettingsPage(SettingsViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    protected override void OnLoaded(RoutedEventArgs e)
    {
        base.OnLoaded(e);
        foreach (var nb in this.GetVisualDescendants().OfType<NumberBox>())
        {
            nb.ValueChanged += NumberBox_ValueChanged;
            if (nb.NumberFormatter != null)
            {
                nb.GotFocus += NumberBox_GotFocus;
                var textBox = nb.GetVisualDescendants().OfType<TextBox>().FirstOrDefault();
                if (textBox != null)
                    textBox.LostFocus += InnerTextBox_LostFocus;
            }
        }
    }

    protected override void OnUnloaded(RoutedEventArgs e)
    {
        base.OnUnloaded(e);
        foreach (var nb in this.GetVisualDescendants().OfType<NumberBox>())
        {
            nb.ValueChanged -= NumberBox_ValueChanged;
            if (nb.NumberFormatter != null)
            {
                nb.GotFocus -= NumberBox_GotFocus;
                var textBox = nb.GetVisualDescendants().OfType<TextBox>().FirstOrDefault();
                if (textBox != null)
                    textBox.LostFocus -= InnerTextBox_LostFocus;
            }
        }
    }

    private static void NumberBox_GotFocus(object? sender, GotFocusEventArgs e)
    {
        if (sender is not NumberBox nb) return;
        var textBox = nb.GetVisualDescendants().OfType<TextBox>().FirstOrDefault();
        if (textBox?.Text != null && textBox.Text.EndsWith("s", StringComparison.OrdinalIgnoreCase))
            textBox.Text = textBox.Text[..^1];
    }

    private static void InnerTextBox_LostFocus(object? sender, RoutedEventArgs e)
    {
        if (sender is not TextBox tb) return;
        if (tb.Text?.EndsWith("s", StringComparison.OrdinalIgnoreCase) == true)
            tb.Text = tb.Text[..^1];
    }

    private static void NumberBox_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs e)
    {
        if (double.IsNaN(e.NewValue))
            sender.Value = sender.Minimum;
    }
}
