// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.App;
using KeePassPasskeyProvider.App.Prompts;
using KeePassPasskeyProvider.App.ViewModel;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyProvider.Util;
using KeePassPasskeyShared.Ipc;
using KeePassPasskeyShared.Settings;

namespace KeePassPasskeyProvider.Authenticator.UserVerification;

/// <summary>
/// Confirmation prompts as our own windows: unaffected by Focus Assist and notification settings,
/// no 5-item picker limit, and the whole registration choice fits in one window.
/// </summary>
internal sealed class DialogUserVerifier : IUserVerifier
{
	public UserVerificationMode Mode => UserVerificationMode.Notification;

	private sealed record RegistrationChoice(bool Approved, DatabaseInfo? Database, EntryTargetInfo? Entry)
	{
		internal static readonly RegistrationChoice Cancelled = new(false, null, null);
	}

	public int VerifyForRegistration(RegistrationVerification request, CancellationToken cancellation,
		out DatabaseInfo? selectedDatabase, out EntryTargetInfo? selectedEntry)
	{
		selectedDatabase = null;
		selectedEntry = null;

		var choice = PromptHost.Show(
			tcs =>
			{
				var viewModel = new RegistrationPromptViewModel(request);
				var window = new RegistrationPromptWindow(viewModel);
				window.Closed += (_, _) => tcs.TrySetResult(viewModel.Approved
					? new RegistrationChoice(true, viewModel.TargetDatabase, viewModel.TargetEntry)
					: RegistrationChoice.Cancelled);
				return window;
			},
			OwnerWindow(request.RequestPtr), RegistrationChoice.Cancelled, cancellation);

		if (!choice.Approved) return HResults.NTE_USER_CANCELLED;

		selectedDatabase = choice.Database;
		selectedEntry = choice.Entry;
		return HResults.S_OK;
	}

	public int VerifyForSignIn(SignInVerification request, CancellationToken cancellation)
	{
		bool approved = PromptHost.Show(
			tcs =>
			{
				var viewModel = new SignInPromptViewModel(request.RpId, request.UserName, request.DisplayHint);
				var window = new SignInPromptWindow(viewModel);
				window.Closed += (_, _) => tcs.TrySetResult(viewModel.Approved);
				return window;
			},
			OwnerWindow(request.RequestPtr), false, cancellation);

		return approved ? HResults.S_OK : HResults.NTE_USER_CANCELLED;
	}

	private static unsafe nint OwnerWindow(nint pRequest)
	{
		if (pRequest == 0) return Win32Native.GetForegroundWindow();
		var request = (WebAuthnPluginOperationRequest*)pRequest;
		return request->hWnd != 0 ? request->hWnd : Win32Native.GetForegroundWindow();
	}
}
