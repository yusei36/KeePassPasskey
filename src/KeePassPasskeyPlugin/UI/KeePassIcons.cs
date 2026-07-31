// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
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

	// KeePass custom icons keep their original size, which can be far larger than any prompt shows them.
	private const int MaxIconPixels = 64;

	private static readonly Dictionary<int, string> StandardIconData = new Dictionary<int, string>();

	/// <summary>The entry's icon as a base64 PNG for the pipe, or null when it cannot be resolved.</summary>
	internal static string EncodeEntryIcon(IPluginHost host, PwDatabase db, PwEntry entry)
	{
		try
		{
			if (entry.CustomIconUuid != null && !entry.CustomIconUuid.Equals(PwUuid.Zero))
				return Encode(db?.GetCustomIcon(entry.CustomIconUuid, MaxIconPixels, MaxIconPixels));

			// Standard icons are shared by many entries, so encoding them once is worth caching.
			int id = (int)entry.IconId;
			if (StandardIconData.TryGetValue(id, out string cached)) return cached;

			string encoded = Encode(GetEntryIcon(host, entry.IconId));
			StandardIconData[id] = encoded;
			return encoded;
		}
		catch (Exception ex)
		{
			Log.Warn($"entry icon could not be encoded: {ex.Message}");
			return null;
		}
	}

	private static string Encode(Image img)
	{
		if (img == null) return null;
		using (var ms = new MemoryStream())
		{
			if (img.Width > MaxIconPixels || img.Height > MaxIconPixels)
			{
				using (var scaled = new Bitmap(img, new Size(MaxIconPixels, MaxIconPixels)))
					scaled.Save(ms, ImageFormat.Png);
			}
			else
			{
				img.Save(ms, ImageFormat.Png);
			}
			return Convert.ToBase64String(ms.ToArray());
		}
	}
}
