// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;

namespace KeePassPasskeyShared;

public static class PluginLogFile
{
	public static readonly string DirectoryPath = Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
		"KeePassPasskey");

	public const string FileName = "Plugin.log";

	public static readonly string FilePath = Path.Combine(DirectoryPath, FileName);
}
