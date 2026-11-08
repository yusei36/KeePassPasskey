// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Resources;

namespace KeePassPasskeyShared.Localization;

/// <summary>
/// Reads every language from the owning assembly itself (<c>{baseName}.{culture}.resources</c>)
/// instead of satellite assemblies, which the ILRepack merge of the plugin would drop.
/// </summary>
public sealed class EmbeddedResourceManager : ResourceManager
{
	private readonly Assembly _assembly;
	private readonly string _baseName;
	private readonly ConcurrentDictionary<string, ResourceSet> _sets = new(StringComparer.OrdinalIgnoreCase);

	public EmbeddedResourceManager(string baseName, Assembly assembly)
		: base(baseName, assembly)
	{
		_assembly = assembly;
		_baseName = baseName;
	}

	/// <summary>
	/// Swaps the ResourceManager of an MSBuild-generated strongly typed resource class for this one.
	/// </summary>
	public static void Install(
#if NET
		// Keeps the trimmer from dropping the private field that is set by reflection.
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.NonPublicFields)]
#endif
		Type stronglyTypedClass)
	{
		var field = stronglyTypedClass.GetField("resourceMan", BindingFlags.Static | BindingFlags.NonPublic)
			?? throw new InvalidOperationException("Generated resource class has no resourceMan field: " + stronglyTypedClass.FullName);
		if (field.GetValue(null) is EmbeddedResourceManager)
			return;
		field.SetValue(null, new EmbeddedResourceManager(stronglyTypedClass.FullName, stronglyTypedClass.Assembly));
	}

	protected override ResourceSet InternalGetResourceSet(CultureInfo culture, bool createIfNotExists, bool tryParents)
	{
		for (var c = culture; ; c = c.Parent)
		{
			var set = _sets.GetOrAdd(c.Name, Load);
			if (set != null || !tryParents || c.Equals(CultureInfo.InvariantCulture))
				return set;
		}
	}

	private ResourceSet Load(string cultureName)
	{
		string name = cultureName.Length == 0 ? _baseName + ".resources" : _baseName + "." + cultureName + ".resources";
		var stream = _assembly.GetManifestResourceStream(name);
		return stream == null ? null : new ResourceSet(stream);
	}
}
