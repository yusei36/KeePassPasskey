// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using KeePassPasskey.Localization;
using KeePassPasskeyShared.Localization;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class LocalizationTests
{
	private static readonly Regex Placeholder = new(@"\{(\d+)(?:[,:][^}]*)?\}", RegexOptions.Compiled);

	[Fact]
	public void Strings_ResolveGerman_AndFallBackToEnglish()
	{
		try
		{
			Localizer.Apply(CultureInfo.GetCultureInfo("de-DE"));
			Assert.Equal("Passkey kopieren", Strings.KeePass_EntryMenu_Copy);
			Assert.Equal("Das Plugin konnte nicht geschrieben werden.", Strings.Common_Install_Error_WriteFailed);

			Localizer.Apply(CultureInfo.GetCultureInfo("fr"));
			Assert.Equal("Copy Passkey", Strings.KeePass_EntryMenu_Copy);
			Assert.Equal("The plugin could not be written.", Strings.Common_Install_Error_WriteFailed);
		}
		finally
		{
			Localizer.Apply(CultureInfo.GetCultureInfo("en"));
		}
	}

	[Fact]
	public void EmbeddedResourceManager_MissingKeyInCulture_FallsBackToNeutral()
	{
		var rm = new EmbeddedResourceManager("KeePassPasskeyShared.Localization.Strings", typeof(Strings).Assembly);
		Assert.Equal("Copy Passkey", rm.GetString(nameof(Strings.KeePass_EntryMenu_Copy), CultureInfo.InvariantCulture));
		Assert.Equal("Passkey kopieren", rm.GetString(nameof(Strings.KeePass_EntryMenu_Copy), CultureInfo.GetCultureInfo("de-AT")));
		Assert.Null(rm.GetString("No_Such_Key", CultureInfo.GetCultureInfo("de")));
	}

	[Theory]
	[InlineData("", "en")]
	[InlineData(null, "en")]
	[InlineData("de", "de")]
	[InlineData("xx-not-a-culture-zz", "en")]
	public void PluginLanguage_Resolve(string? code, string expected)
	{
		Assert.Equal(expected, PluginLanguage.Resolve(code!).Name);
	}

	public static IEnumerable<object[]> ResxFiles() =>
		Directory.GetFiles(LocalizationDir(), "Strings*.resx").Select(f => new object[] { Path.GetFileName(f) });


	/// <summary>Keys follow Component_Area_Element[_Kind], see README "Translating".</summary>
	[Fact]
	public void NeutralKeys_FollowNamingSchema()
	{
		var schema = new Regex(@"^(Common|App|Prompt|Notify|Tray|KeePass)(_[A-Z][A-Za-z0-9]*){1,3}$");
		var invalid = ReadResx(Path.Combine(LocalizationDir(), NeutralFile)).Keys.Where(k => !schema.IsMatch(k)).ToList();
		Assert.True(invalid.Count == 0, "Keys outside the naming schema: " + string.Join(", ", invalid));
	}

	/// <summary>Placeholders and **marked** parts need a translator comment saying what they stand for.</summary>
	[Fact]
	public void NeutralEntries_WithPlaceholders_HaveComments()
	{
		var missing = XDocument.Load(Path.Combine(LocalizationDir(), NeutralFile)).Root!.Elements("data")
			.Where(d => (Placeholder.IsMatch((string?)d.Element("value") ?? "") || ((string?)d.Element("value") ?? "").Contains("**"))
				&& string.IsNullOrWhiteSpace((string?)d.Element("comment")))
			.Select(d => (string)d.Attribute("name")!)
			.ToList();
		Assert.True(missing.Count == 0, "Missing translator comments: " + string.Join(", ", missing));
	}

	/// <summary>Sorted files keep related keys together and a translation diff reviewable.</summary>
	[Theory]
	[MemberData(nameof(ResxFiles))]
	public void ResxKeys_AreSorted(string fileName)
	{
		var keys = ReadResx(Path.Combine(LocalizationDir(), fileName)).Keys.ToList();
		var sorted = keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).ToList();
		int first = Enumerable.Range(0, keys.Count).Where(i => keys[i] != sorted[i]).DefaultIfEmpty(-1).First();
		Assert.True(first < 0, first < 0 ? "" : "Not sorted at " + keys[first] + ", expected " + sorted[first]);
	}

	/// <summary>
	/// A translation may lack keys (they fall back to English) but must not invent keys or change
	/// placeholders, either of which only shows up at runtime.
	/// </summary>
	[Fact]
	public void Translations_MatchNeutralKeysAndPlaceholders()
	{
		var neutral = ReadResx(Path.Combine(LocalizationDir(), NeutralFile));
		var problems = new List<string>();
		foreach (string path in Directory.GetFiles(LocalizationDir(), "Strings.*.resx"))
		{
			var translated = ReadResx(path);
			string file = Path.GetFileName(path);
			problems.AddRange(translated.Keys.Except(neutral.Keys).Select(k => file + ": unknown key " + k));
			problems.AddRange(translated
				.Where(kv => neutral.ContainsKey(kv.Key) && !Placeholders(kv.Value).SetEquals(Placeholders(neutral[kv.Key])))
				.Select(kv => file + ": placeholders differ in " + kv.Key));
		}
		Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
	}

	private const string NeutralFile = "Strings.resx";

	private static Dictionary<string, string> ReadResx(string path) =>
		XDocument.Load(path).Root!.Elements("data")
			.ToDictionary(d => (string)d.Attribute("name")!, d => (string?)d.Element("value") ?? "");

	private static HashSet<string> Placeholders(string value) =>
		new(Placeholder.Matches(value).Cast<Match>().Select(m => m.Groups[1].Value));

	private static string LocalizationDir([CallerFilePath] string thisFile = "") =>
		Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(thisFile))!, "KeePassPasskeyShared", "Localization");
}
