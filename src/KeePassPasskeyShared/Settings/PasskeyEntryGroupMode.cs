// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace KeePassPasskeyShared.Settings;

[JsonConverter(typeof(StringEnumConverter))]
public enum PasskeyEntryGroupMode
{
	PasskeysGroup = 0,
	SelectedGroup = 1,
}
