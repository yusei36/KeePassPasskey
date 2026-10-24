// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
namespace KeePassPasskey.Update;

internal enum PluginUpdateChoice
{
	Later,
	Update,
	SkipThisVersion,
}

internal sealed class PluginUpdateInfo
{
	internal string InstalledVersion;
	internal string AvailableVersion;
	internal string ChannelDisplayName;
	internal string PackagePath;
	internal string TargetDirectory;
}
