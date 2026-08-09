// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using KeePass.Plugins;
using KeePassPasskey.Storage;
using KeePassPasskey.UI;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskey.Update;

/// <summary>
/// Offers to replace the loaded plugin DLL with the newer one bundled in the installed provider
/// package. The provider updates itself while the plugin does not, so without this the two halves
/// drift apart until a passkey operation fails.
/// </summary>
internal sealed class PluginUpdateChecker : IDisposable
{
	private readonly IPluginHost _host;
	private readonly SettingsStorage _settingsStorage;
	private bool _checked;

	internal PluginUpdateChecker(IPluginHost host, SettingsStorage settingsStorage)
	{
		_host = host;
		_settingsStorage = settingsStorage;

		if (_host.MainWindow != null)
			_host.MainWindow.Shown += OnMainWindowShown;
	}

	public void Dispose()
	{
		if (_host.MainWindow != null)
			_host.MainWindow.Shown -= OnMainWindowShown;
	}

	private void OnMainWindowShown(object sender, EventArgs e)
	{
		_host.MainWindow.Shown -= OnMainWindowShown;

		// Queued so the prompt lands after KeePass's own startup work, master key dialog included.
		_host.MainWindow.BeginInvoke(new Action(() => Check(false)));
	}

	/// <summary>Runs the check. <paramref name="force"/> ignores the setting and the skipped version.</summary>
	internal void Check(bool force)
	{
		try
		{
			if (_checked && !force) return;
			_checked = true;

			var settings = _settingsStorage.Load();
			if (!settings.CheckForPluginUpdates && !force)
				return;

			string targetDirectory = PluginLocation.DirectoryPath;
			string installedVersion = PluginLocation.InstalledVersion;
			if (targetDirectory == null || installedVersion == null)
			{
				Log.Debug("plugin update check skipped: plugin location unknown");
				if (force) ReportNoUpdate("The plugin file could not be located, so it cannot be updated from here.");
				return;
			}

			var package = ProviderPackageLocator.FindNewestBundledPlugin(m => Log.Warn(m));
			string availableVersion = package?.BundledPluginVersion;
			if (availableVersion == null)
			{
				Log.Debug("plugin update check: no installed package ships a plugin");
				if (force) ReportNoUpdate("The KeePassPasskey app does not seem to be installed.");
				return;
			}

			if (PipeConstants.CompareProductVersions(availableVersion, installedVersion) <= 0)
			{
				if (force) ReportNoUpdate("Version " + PipeConstants.StripBuildMetadata(installedVersion)
					+ " is the newest version the installed KeePassPasskey app provides.");
				return;
			}

			if (!force && SameVersion(availableVersion, _settingsStorage.LoadSkippedPluginVersion()))
			{
				Log.Debug("plugin update " + availableVersion + " skipped by the user");
				return;
			}

			Prompt(package, new PluginUpdateInfo
			{
				InstalledVersion = installedVersion,
				AvailableVersion = availableVersion,
				ChannelDisplayName = package.ChannelDisplayName,
				PackagePath = package.InstallPath,
				TargetDirectory = targetDirectory,
			});
		}
		catch (Exception ex)
		{
			Log.Warn("plugin update check failed: " + ex.Message);
		}
	}

	private void Prompt(ProviderPackage package, PluginUpdateInfo info)
	{
		Log.Info("offering plugin update " + info.InstalledVersion + " -> " + info.AvailableVersion
			+ " from " + package.PackageFamilyName);

		PluginUpdateChoice choice;
		bool restart;
		using (var form = new PluginUpdateForm(info, () => PluginInstallLauncher.Install(
			package.BundledPluginDllPath, info.TargetDirectory, package.InstallScriptPath)))
		{
			form.ShowDialog(_host.MainWindow);
			choice = form.Choice;
			restart = form.RestartRequested;
			if (form.InstallOutcome != null)
			{
				Log.Info("plugin update result: " + form.InstallOutcome.Result
					+ (form.InstallOutcome.Elevated ? " (elevated)" : "")
					+ (form.InstallOutcome.Error != null ? " - " + form.InstallOutcome.Error : ""));
			}
		}

		switch (choice)
		{
			case PluginUpdateChoice.SkipThisVersion:
				_settingsStorage.SaveSkippedPluginVersion(info.AvailableVersion);
				break;
			case PluginUpdateChoice.NeverCheck:
				var settings = _settingsStorage.Load();
				settings.CheckForPluginUpdates = false;
				_settingsStorage.Save(settings);
				break;
		}

		if (restart)
			Restart();
	}

	// KeePass forwards a second instance to the running one and exits it, so the new process can
	// only be started once this one is on its way out.
	private void Restart()
	{
		System.Windows.Forms.FormClosedEventHandler handler = null;
		handler = (s, e) =>
		{
			_host.MainWindow.FormClosed -= handler;
			KeePass.Util.WinUtil.Restart();
		};
		_host.MainWindow.FormClosed += handler;
		_host.MainWindow.Close();

		// A refused close (unsaved changes, minimize to tray) must not leave a later exit restarting.
		if (!_host.MainWindow.IsDisposed)
			_host.MainWindow.FormClosed -= handler;
	}

	private static void ReportNoUpdate(string message) =>
		KeePassLib.Utility.MessageService.ShowInfo("KeePassPasskey plugin", message);

	private static bool SameVersion(string a, string b) =>
		!string.IsNullOrEmpty(b) &&
		string.Equals(PipeConstants.StripBuildMetadata(a), PipeConstants.StripBuildMetadata(b),
			StringComparison.OrdinalIgnoreCase);
}
