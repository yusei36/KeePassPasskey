// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FluentAvalonia.UI.Controls;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyProvider.Authenticator;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Update;

namespace KeePassPasskeyProvider.App.ViewModel;

public enum PluginInstallState { UnknownPath, NotInstalled, UpToDate, Outdated, Newer }

public sealed partial class PluginInstallViewModel : ObservableObject
{
	[ObservableProperty] public partial string SelectedFolder { get; set; } = "";
	[ObservableProperty] public partial string DetectionSource { get; set; } = "";
	[ObservableProperty] public partial PluginInstallState State { get; set; }
	[ObservableProperty] public partial string StatusText { get; set; } = "";
	[ObservableProperty] public partial string TargetDllPath { get; set; } = "";
	[ObservableProperty] public partial bool ShowCreateNote { get; set; }
	[ObservableProperty] public partial bool NeedsElevation { get; set; }
	[ObservableProperty] public partial string? ResultMessage { get; set; }
	[ObservableProperty] public partial FAInfoBarSeverity ResultSeverity { get; set; }
	[ObservableProperty] public partial bool IsBusy { get; set; }
	[ObservableProperty] public partial string BusyText { get; set; } = "";

	public string SourceCaption { get; } =
		$"Installs from KeePassPasskey ({PluginConstants.ChannelDisplayName}) "
		+ PipeConstants.StripBuildMetadata(PipeConstants.Version);

	public string SourcePath { get; } = ProviderCommands.BundledPluginDll ?? "";

	public bool ShowResult => ResultMessage != null;

	public bool CanInstall => State != PluginInstallState.UnknownPath;
	public bool CanRemove => State is PluginInstallState.UpToDate or PluginInstallState.Outdated or PluginInstallState.Newer;

	public string PrimaryActionText => State switch
	{
		PluginInstallState.UpToDate => "Reinstall",
		PluginInstallState.Outdated or PluginInstallState.Newer => "Update",
		_ => "Install",
	};

	/// <summary>Reinstalling an up-to-date file is a repair route, not something to invite.</summary>
	public bool EmphasizePrimary => State != PluginInstallState.UpToDate;

	public bool StatusIsError => State == PluginInstallState.UnknownPath;
	public bool StatusIsOk => State == PluginInstallState.UpToDate;

	public ICommand ShowPluginFileCommand => ProviderCommands.ShowPluginFileCommand;

	private readonly string _detectedFolder;
	private readonly string _detectedSource;
	private string? _targetDirectory;

	public PluginInstallViewModel()
	{
		var located = KeePassLocator.Locate();
		_detectedFolder = located?.Directory ?? "";
		_detectedSource = located != null
			? "Detected from " + located.Source + "."
			: "KeePass was not found. Enter or browse to its folder, or to its Plugins folder.";

		SelectedFolder = _detectedFolder;
		UpdateDetectionSource();
		Refresh();
	}

	partial void OnSelectedFolderChanged(string value)
	{
		UpdateDetectionSource();
		Refresh();
	}

	// A hand-typed path must not keep claiming a source, but the detected install's own Plugins
	// folder is still that install.
	private void UpdateDetectionSource() =>
		DetectionSource = string.Equals(SelectedFolder, _detectedFolder, StringComparison.OrdinalIgnoreCase)
			|| SameTargetDirectory(SelectedFolder, _detectedFolder)
				? _detectedSource
				: "";

	private static bool SameTargetDirectory(string a, string b)
	{
		string? resolved = KeePassLocator.ResolveTargetDirectory(a);
		return resolved != null && string.Equals(resolved,
			KeePassLocator.ResolveTargetDirectory(b), StringComparison.OrdinalIgnoreCase);
	}

	partial void OnResultMessageChanged(string? value) => OnPropertyChanged(nameof(ShowResult));

	partial void OnStateChanged(PluginInstallState value)
	{
		OnPropertyChanged(nameof(CanInstall));
		OnPropertyChanged(nameof(CanRemove));
		OnPropertyChanged(nameof(PrimaryActionText));
		OnPropertyChanged(nameof(EmphasizePrimary));
		OnPropertyChanged(nameof(StatusIsError));
		OnPropertyChanged(nameof(StatusIsOk));
	}

	[RelayCommand]
	private void ShowTargetFolder()
	{
		if (_targetDirectory == null) return;
		Process.Start(new ProcessStartInfo
		{
			FileName = "explorer.exe",
			Arguments = File.Exists(TargetDllPath) ? $"/select,\"{TargetDllPath}\"" : $"\"{_targetDirectory}\"",
		});
	}

	private void Refresh()
	{
		ResultMessage = null;

		_targetDirectory = KeePassLocator.ResolveTargetDirectory(SelectedFolder);
		if (_targetDirectory == null)
		{
			State = PluginInstallState.UnknownPath;
			TargetDllPath = "";
			ShowCreateNote = false;
			NeedsElevation = false;
			StatusText = string.IsNullOrWhiteSpace(SelectedFolder)
				? "No folder chosen."
				: "This is not a KeePass folder or one of its plugin folders. "
					+ "Point it at the KeePass folder or its Plugins subfolder.";
			return;
		}

		TargetDllPath = Path.Combine(_targetDirectory, PluginInstaller.PluginDllName);
		ShowCreateNote = !Directory.Exists(_targetDirectory);
		NeedsElevation = RequiresElevation(_targetDirectory);

		string? installed = ReadVersion(TargetDllPath);
		string bundled = PipeConstants.StripBuildMetadata(PipeConstants.Version);

		if (installed == null)
		{
			State = PluginInstallState.NotInstalled;
			StatusText = "Not installed.";
			return;
		}

		int order = PipeConstants.CompareProductVersions(bundled, installed);
		State = order switch
		{
			> 0 => PluginInstallState.Outdated,
			< 0 => PluginInstallState.Newer,
			_ => PluginInstallState.UpToDate,
		};
		StatusText = State switch
		{
			PluginInstallState.Outdated => $"Version {installed} is installed, {bundled} is available.",
			PluginInstallState.Newer => $"Version {installed} is installed, which is newer than this app's {bundled}.",
			_ => $"Version {installed} is installed and up to date.",
		};
	}

	[RelayCommand]
	private async Task InstallAsync()
	{
		await RunAsync(() => PluginInstallLauncher.Install(
			ProviderCommands.BundledPluginDll!,
			_targetDirectory!,
			ProviderCommands.InstallScript!), "installed", "Installing...");
	}

	[RelayCommand]
	private async Task RemoveAsync()
	{
		await RunAsync(() => PluginInstallLauncher.Remove(
			_targetDirectory!,
			ProviderCommands.InstallScript!), "removed", "Removing...");
	}

	private async Task RunAsync(Func<PluginInstallOutcome> action, string pastTense, string busyText)
	{
		BusyText = busyText;
		IsBusy = true;
		ResultMessage = null;
		try
		{
			var outcome = await Task.Run(action);
			Log.Info($"plugin {pastTense}: {outcome.Result}{(outcome.Elevated ? " (elevated)" : "")}");

			if (outcome.Cancelled)
			{
				ResultSeverity = FAInfoBarSeverity.Informational;
				ResultMessage = "Cancelled at the administrator prompt. Nothing was changed.";
			}
			else if (outcome.Success)
			{
				ResultSeverity = FAInfoBarSeverity.Success;
				ResultMessage = IsKeePassRunning()
					? $"The plugin was {pastTense}. Restart KeePass to load the change."
					: $"The plugin was {pastTense}.";
			}
			else
			{
				ResultSeverity = FAInfoBarSeverity.Error;
				ResultMessage = outcome.Error ?? "The plugin could not be written.";
			}
		}
		finally
		{
			IsBusy = false;
			RefreshPreservingResult();
		}
	}

	private void RefreshPreservingResult()
	{
		string? message = ResultMessage;
		var severity = ResultSeverity;
		Refresh();
		ResultMessage = message;
		ResultSeverity = severity;
	}

	// A folder that does not exist yet inherits its permissions from the nearest one that does.
	private static bool RequiresElevation(string directory)
	{
		string? existing = directory;
		while (existing != null && !Directory.Exists(existing))
			existing = Path.GetDirectoryName(existing);

		return existing != null && !PluginInstaller.CanWriteTo(existing);
	}

	private static bool IsKeePassRunning()
	{
		try { return Process.GetProcessesByName("KeePass").Length > 0; }
		catch { return false; }
	}

	private static string? ReadVersion(string dllPath)
	{
		try
		{
			return File.Exists(dllPath)
				? PipeConstants.StripBuildMetadata(FileVersionInfo.GetVersionInfo(dllPath).ProductVersion ?? "")
				: null;
		}
		catch { return null; }
	}
}
