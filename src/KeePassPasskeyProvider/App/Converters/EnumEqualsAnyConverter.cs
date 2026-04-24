using System.Globalization;
using Avalonia.Data.Converters;

namespace KeePassPasskeyProvider.App.Converters;

internal sealed class EnumEqualsAnyConverter : IValueConverter
{
    public static readonly EnumEqualsAnyConverter Instance = new(negate: false);
    public static readonly EnumEqualsAnyConverter Negated  = new(negate: true);

    private readonly bool _negate;
    private EnumEqualsAnyConverter(bool negate) => _negate = negate;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (parameter is not string param) return _negate;
        var target = value?.ToString();
        bool matches = target is not null && param.Split(',').Any(v => v.Trim() == target);
        return _negate ? !matches : matches;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
