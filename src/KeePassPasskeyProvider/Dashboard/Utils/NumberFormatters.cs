// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskeyProvider.Dashboard.Utils;

internal static class NumberFormatters
{
    public static Func<double, string> Seconds { get; } = v => $"{v:0}s";
}
