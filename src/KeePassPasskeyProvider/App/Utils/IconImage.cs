// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using Avalonia.Media.Imaging;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>Decodes the base64 PNG entry icons the plugin sends, so prompts can show the real icon.</summary>
internal static class IconImage
{
	internal static IImage? FromBase64(string? data)
	{
		if (string.IsNullOrEmpty(data)) return null;
		try
		{
			using var stream = new MemoryStream(Convert.FromBase64String(data));
			return new Bitmap(stream);
		}
		catch (Exception ex)
		{
			Log.Debug($"entry icon could not be decoded: {ex.GetType().Name}: {ex.Message}", nameof(IconImage));
			return null;
		}
	}
}
