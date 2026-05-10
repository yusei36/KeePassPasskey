namespace KeePassPasskeyProvider.Dashboard.Utils;

internal static class NumberFormatters
{
    public static Func<double, string> Seconds { get; } = v => $"{v:0}s";
}
