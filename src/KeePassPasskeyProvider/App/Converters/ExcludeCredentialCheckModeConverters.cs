// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Data.Converters;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.App.Converters;

internal static class ExcludeCredentialCheckModeConverters
{
    public static readonly IValueConverter Text = new LambdaConverter(v => (v as ExcludeCredentialCheckMode?) switch
    {
        ExcludeCredentialCheckMode.None         => "Don't check",
        ExcludeCredentialCheckMode.AllDatabases => "Check all databases",
        _                                       => "Check target database",
    });
}
