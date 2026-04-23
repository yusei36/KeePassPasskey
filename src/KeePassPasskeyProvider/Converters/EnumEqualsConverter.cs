using System.Globalization;
using Avalonia.Data.Converters;

namespace KeePassPasskeyProvider.Converters;

internal sealed class EnumEqualsConverter : IValueConverter
{
    public static readonly EnumEqualsConverter Instance = new(negate: false);
    public static readonly EnumEqualsConverter Negated  = new(negate: true);

    private readonly bool _negate;
    private EnumEqualsConverter(bool negate) => _negate = negate;

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool equals = Equals(value, parameter);
        return _negate ? !equals : equals;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
