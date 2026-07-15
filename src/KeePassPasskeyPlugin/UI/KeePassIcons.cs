// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using KeePass.Plugins;
using KeePassLib;
using KeePassPasskeyShared;

namespace KeePassPasskey.UI;

internal static class KeePassIcons
{
	private static readonly Type ResourcesType =
		typeof(KeePass.Program).Assembly.GetType("KeePass.Properties.Resources");

	private static readonly Dictionary<string, Image> Cache =
		new Dictionary<string, Image>(StringComparer.Ordinal);

	internal static Image Get(string name)
	{
		if (Cache.TryGetValue(name, out var cached)) return cached;

		Image img = null;
		try
		{
			var prop = ResourcesType?.GetProperty(name,
				BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
			img = prop?.GetValue(null) as Image;
			if (img == null)
				Log.Warn($"KeePass icon '{name}' not found");
		}
		catch (Exception ex)
		{
			Log.Warn($"KeePass icon '{name}' unavailable: {ex.Message}");
		}

		Cache[name] = img;
		return img;
	}

	internal static Image GetEntryIcon(IPluginHost host, PwIcon icon)
	{
		try
		{
			var images = host?.MainWindow?.ClientIcons?.Images;
			int i = (int)icon;
			if (images != null && i >= 0 && i < images.Count) return images[i];
		}
		catch (Exception ex) { Log.Warn($"entry icon {icon} unavailable: {ex.Message}"); }
		return null;
	}
}
