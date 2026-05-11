// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Kögel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings
{
    [Flags]
    [JsonConverter(typeof(StringEnumConverter))]
    public enum UserVerificationMode
    {
        None         = 0,
        WindowsHello = 1,
        Notification = 2,
        Both         = WindowsHello | Notification,
    }
}
