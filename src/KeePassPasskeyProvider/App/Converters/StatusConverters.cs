using System.Globalization;
using Avalonia.Data.Converters;
using KeePassPasskey.Shared.Ipc;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Converters;

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
    public static readonly IValueConverter Text = Make(v => (v as PingStatus? ?? PingStatus.NotConnected) switch
    {
        PingStatus.Ready               => "Running",
        PingStatus.NoDatabase          => "No database open",
        PingStatus.IncompatibleVersion => "Incompatible version",
        _                              => "Not connected",
    });

    private static IValueConverter Make(Func<object?, object?> convert) => new LambdaConverter(convert);
}

file sealed class LambdaConverter(Func<object?, object?> convert) : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => convert(value);

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
