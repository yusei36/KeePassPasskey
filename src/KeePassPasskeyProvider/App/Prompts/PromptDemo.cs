// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
#if DEBUG
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.App.Prompts;

/// <summary>Debug-only harness (<c>/promptdemo</c>): both prompts with sample data.</summary>
internal static class PromptDemo
{
	internal static int Run()
	{
		// Stands in for the browser window a real ceremony hands us.
		nint owner = Util.Win32Native.GetForegroundWindow();
		Log.Info($"demo owner window 0x{owner:X}", nameof(PromptDemo));

		var databases = new List<DatabaseInfo>
		{
			new() { Id = "db1", Name = "Personal.kdbx" },
			new() { Id = "db2", Name = "Work.kdbx" },
			new() { Id = "db3", Name = "Archive.kdbx" },
		};

		var candidates = new List<EntryMatchInfo>
		{
			Entry("e1", "db1", "Personal.kdbx", "Personal Email", hasPasskey: false, selected: true),
			Entry("e2", "db2", "Work.kdbx", "Work Portal", hasPasskey: false, selected: false),
			Entry("e3", "db1", "Personal.kdbx", "example.com Shop", hasPasskey: true, selected: false),
			Entry("e4", "db1", "Personal.kdbx", "Forum Account", hasPasskey: false, selected: false),
			Entry("e5", "db3", "Archive.kdbx", "Backup Login", hasPasskey: true, selected: false),
			Entry("e6", "db1", "Personal.kdbx", "Old Account With A Very Long Title That Should Be Trimmed", hasPasskey: false, selected: false),
			Entry("e7", "db2", "Work.kdbx", "Shared Team Login", hasPasskey: true, selected: false),
			Entry("e8", "db3", "Archive.kdbx", "Retired Account", hasPasskey: false, selected: false),
		};

		var choice = PromptHost.Show<(bool Approved, string Target)>(
			tcs =>
			{
				var viewModel = new RegistrationPromptViewModel("example.com", "Example", "jordan@example.com", databases, candidates);
				var window = new RegistrationPromptWindow(viewModel);
				window.Closed += (_, _) => tcs.TrySetResult((
					viewModel.Approved,
					viewModel.TargetEntry?.EntryUuid ?? viewModel.TargetDatabase?.Name ?? "(none)"));
				return window;
			},
			owner, (false, "(cancelled)"), CancellationToken.None);

		Log.Info($"registration prompt: approved={choice.Approved} target={choice.Target}", nameof(PromptDemo));

		bool signedIn = PromptHost.Show(
			tcs =>
			{
				var viewModel = new SignInPromptViewModel("example.com", "jordan@example.com", "Personal Email");
				var window = new SignInPromptWindow(viewModel);
				window.Closed += (_, _) => tcs.TrySetResult(viewModel.Approved);
				return window;
			},
			owner, false, CancellationToken.None);

		Log.Info($"sign-in prompt: approved={signedIn}", nameof(PromptDemo));
		return 0;
	}

	private static EntryMatchInfo Entry(string uuid, string dbId, string dbName, string title, bool hasPasskey, bool selected)
		=> new()
		{
			EntryUuid = uuid,
			DatabaseId = dbId,
			DatabaseName = dbName,
			Title = title,
			HasPasskey = hasPasskey,
			IsSelected = selected,
		};
}
#endif
