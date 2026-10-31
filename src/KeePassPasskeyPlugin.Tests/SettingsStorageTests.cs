// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Xml;
using KeePassPasskey.Storage;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class SettingsStorageTests
{
	private const string Key = "KeePassPasskey.Settings";

	private static XmlDocument Enforced(string customItems)
	{
		var doc = new XmlDocument();
		doc.LoadXml($"<?xml version=\"1.0\" encoding=\"utf-8\"?><Configuration><Custom>{customItems}</Custom></Configuration>");
		return doc;
	}

	[Fact]
	public void NoEnforcedFile_IsNotEnforced()
	{
		Assert.Null(SettingsStorage.FindEnforcedValue(null, Key));
	}

	[Fact]
	public void OtherKeysOnly_IsNotEnforced()
	{
		var doc = Enforced("<Item><Key>OtherPlugin.Setting</Key><Value>1</Value></Item>");
		Assert.Null(SettingsStorage.FindEnforcedValue(doc, Key));
	}

	[Fact]
	public void MatchingKey_ReturnsItsValue()
	{
		var doc = Enforced(
			"<Item><Key>OtherPlugin.Setting</Key><Value>1</Value></Item>" +
			$"<Item><Key>{Key}</Key><Value>{{\"checkForPluginUpdates\":false}}</Value></Item>");
		Assert.Equal("{\"checkForPluginUpdates\":false}", SettingsStorage.FindEnforcedValue(doc, Key));
	}

	// An empty value still enforces: the defaults.
	[Fact]
	public void EmptyValue_IsEnforced()
	{
		var doc = Enforced($"<Item><Key>{Key}</Key><Value></Value></Item>");
		Assert.Equal("", SettingsStorage.FindEnforcedValue(doc, Key));
	}

	[Fact]
	public void RemoveMode_IsNotEnforced()
	{
		var doc = Enforced($"<Item MergeNodeMode=\"Remove\"><Key>{Key}</Key></Item>");
		Assert.Null(SettingsStorage.FindEnforcedValue(doc, Key));
	}

	[Theory]
	[InlineData("")]
	[InlineData("{\"checkForPluginUpdates\":false}")]
	public void Enforced_DisallowsAaguidSpoofingByDefault(string json)
	{
		Assert.False(SettingsStorage.ParseEnforced(json).AllowAaguidSpoofing);
	}

	[Fact]
	public void Enforced_CanAllowAaguidSpoofingExplicitly()
	{
		Assert.True(SettingsStorage.ParseEnforced("{\"allowAaguidSpoofing\":true}").AllowAaguidSpoofing);
	}

	[Fact]
	public void Enforced_OmittedSettingsKeepClassDefaults()
	{
		var settings = SettingsStorage.ParseEnforced("{\"checkForPluginUpdates\":false}");
		Assert.False(settings.CheckForPluginUpdates);
		Assert.True(settings.ShowErrorNotifications);
		Assert.Equal(60_000, settings.NotificationVerificationTimeoutMilliseconds);
	}

	[Fact]
	public void ItemOutsideCustom_IsIgnored()
	{
		var doc = new XmlDocument();
		doc.LoadXml($"<Configuration><Application><Item><Key>{Key}</Key><Value>{{}}</Value></Item></Application></Configuration>");
		Assert.Null(SettingsStorage.FindEnforcedValue(doc, Key));
	}
}
