using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskeyProvider.ViewModels;

namespace KeePassPasskeyProvider.Converters;

internal static class ProviderStatusConverters
{
    public static readonly IValueConverter Headline = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.AutoregisterFailed => "Automatic registration failed",
        ProviderStatus.NotRegistered      => "Not registered",
        ProviderStatus.WaitingToBeEnabled => "Waiting to be enabled",
        ProviderStatus.VersionMismatch    => "Version mismatch",
        ProviderStatus.NoDatabase         => "No database open",
        ProviderStatus.PluginNotRunning   => "Plugin not running",
        _                                  => "All systems ready",
    });

    public static readonly IValueConverter Subhead = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.AutoregisterFailed => "You can retry by clicking Register.",
        ProviderStatus.NotRegistered      => "KeePassPasskey will register the provider automatically on launch.",
        ProviderStatus.WaitingToBeEnabled => "Enable KeePassPasskey in Windows Settings → Accounts → Passkeys.",
        ProviderStatus.VersionMismatch    => "Update the plugin or the provider so both are on the same version.",
        ProviderStatus.NoDatabase         => "Open a KeePass database to use passkeys.",
        ProviderStatus.PluginNotRunning   => "Start KeePass with the KeePassPasskey plugin installed.",
        _                                  => "Provider is enabled and the KeePass plugin is running.",
    });

    public static readonly IValueConverter RingBorderBrush = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.Ready              => Brushes.Success,
        ProviderStatus.AutoregisterFailed => Brushes.Critical,
        ProviderStatus.NotRegistered      => Brushes.Critical,
        _                                  => Brushes.Warning,
    });

    public static readonly IValueConverter RingBackgroundBrush = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.Ready              => Brushes.SuccessBg,
        ProviderStatus.AutoregisterFailed => Brushes.CriticalBg,
        ProviderStatus.NotRegistered      => Brushes.CriticalBg,
        _                                  => Brushes.WarningBg,
    });

    public static readonly IValueConverter ProviderDotColor = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.Ready or ProviderStatus.PluginNotRunning or
        ProviderStatus.NoDatabase or ProviderStatus.VersionMismatch => Brushes.Success,
        ProviderStatus.WaitingToBeEnabled                            => Brushes.Warning,
        _                                                             => Brushes.Neutral,
    });

    public static readonly IValueConverter ProviderPillText = Make(v => (v as ProviderStatus? ?? ProviderStatus.NotRegistered) switch
    {
        ProviderStatus.Ready or ProviderStatus.PluginNotRunning or
        ProviderStatus.NoDatabase or ProviderStatus.VersionMismatch => "Enabled",
        ProviderStatus.WaitingToBeEnabled                            => "Registered",
        _                                                             => "Not registered",
    });

    private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}

internal static class PingStatusConverters
{
    public static readonly IValueConverter DotColor = Make(v => (v as PingStatus?) switch
    {
        PingStatus.Ready               => Brushes.Success,
        PingStatus.NoDatabase          => Brushes.Warning,
        PingStatus.IncompatibleVersion => Brushes.Critical,
        _                              => Brushes.Neutral,
    });

    public static readonly IValueConverter Text = Make(v => (v as PingStatus?) switch
    {
        PingStatus.Ready               => "Running",
        PingStatus.NoDatabase          => "No database open",
        PingStatus.IncompatibleVersion => "Incompatible version",
        _                              => "Not running",
    });

    private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}

// Shared brush palette
file static class Brushes
{
    public static readonly IBrush Success    = new SolidColorBrush(Color.Parse("#6ccb5f"));
    public static readonly IBrush Warning    = new SolidColorBrush(Color.Parse("#fce100"));
    public static readonly IBrush Critical   = new SolidColorBrush(Color.Parse("#ff99a4"));
    public static readonly IBrush Neutral    = new SolidColorBrush(Color.Parse("#8a8a8a"));
    public static readonly IBrush SuccessBg  = new SolidColorBrush(Color.FromArgb(0x26, 0x6c, 0xcb, 0x5f));
    public static readonly IBrush WarningBg  = new SolidColorBrush(Color.FromArgb(0x1E, 0xfc, 0xe1, 0x00));
    public static readonly IBrush CriticalBg = new SolidColorBrush(Color.FromArgb(0x26, 0xff, 0x99, 0xa4));
}

file sealed class LambdaConverter(Func<object?, object?> convert) : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => convert(value);

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
