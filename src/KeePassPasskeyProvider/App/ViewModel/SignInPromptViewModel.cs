// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using KeePassPasskeyProvider.App.Utils;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>
/// Sign-in prompt: confirm an assertion for the credential Windows already picked. Everything shown
/// comes from the Windows credential cache, which is all the provider knows here.
/// </summary>
public sealed partial class SignInPromptViewModel : PromptViewModelBase
{
	public string CredentialTitle { get; }
	public string CredentialSubtitle { get; }
	public bool HasCredentialSubtitle => CredentialSubtitle.Length > 0;
	public string CredentialLetter { get; }
	public IBrush CredentialTileBrush { get; }

	public override bool CanConfirm => true;

	internal SignInPromptViewModel(string rpId, string userName, string displayHint)
	{
		WindowTitle = "Sign in with passkey";
		ConfirmText = "Sign in";
		SetSite($"{rpId} wants you to sign in", "", rpId);

		CredentialTitle = FirstNonEmpty(displayHint, userName, rpId);
		CredentialSubtitle = string.Equals(CredentialTitle, userName, StringComparison.Ordinal) ? "" : userName;
		CredentialLetter = LetterTile.Letter(CredentialTitle);
		CredentialTileBrush = LetterTile.Brush(CredentialTitle);
	}

	private static string FirstNonEmpty(params string[] candidates)
	{
		foreach (string candidate in candidates)
		{
			if (!string.IsNullOrWhiteSpace(candidate)) return candidate;
		}
		return "";
	}
}
