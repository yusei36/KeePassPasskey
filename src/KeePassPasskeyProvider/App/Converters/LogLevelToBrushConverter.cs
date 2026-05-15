// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Converters;

internal static class LogLevelToBrushConverter
{
    private static readonly IBrush ErrorBrush = new SolidColorBrush(Color.Parse("#CC2222"));
    private static readonly IBrush WarnBrush  = new SolidColorBrush(Color.Parse("#B85E00"));
    private static readonly IBrush DebugBrush = new SolidColorBrush(Color.Parse("#888888"));

    public static readonly IValueConverter Instance = new LevelConverter();

    private sealed class LevelConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
            => (value as LogLevel?) switch
            {
                LogLevel.Error => ErrorBrush,
                LogLevel.Warn  => WarnBrush,
                LogLevel.Debug => DebugBrush,
                _              => null,
            };

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
