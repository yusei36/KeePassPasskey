// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Media;
using KeePassPasskeyProvider.App.Utils;
using KeePassPasskeyProvider.Authenticator.UserVerification;

namespace KeePassPasskeyProvider.App.ViewModel;

/// <summary>
/// Sign-in prompt: confirm an assertion for the credential Windows already picked.
/// </summary>
public sealed partial class SignInPromptViewModel : PromptViewModelBase
{
	public string CredentialTitle { get; }
	public string CredentialSubtitle { get; }
	public bool HasCredentialSubtitle => CredentialSubtitle.Length > 0;
	public string CredentialDatabase { get; }
	public bool HasCredentialDatabase => CredentialDatabase.Length > 0;
	public string CredentialLetter { get; }
	public IBrush CredentialTileBrush { get; }
	public IImage? CredentialIcon { get; }
	public bool HasCredentialIcon => CredentialIcon != null;

	public override bool CanConfirm => true;

	internal SignInPromptViewModel(SignInVerification request)
	{
		WindowTitle = "Sign in with passkey";
		ConfirmText = "Sign in";
		SetSite($"{request.RpId} wants you to sign in", "", request.RpId);

		CredentialTitle = FirstNonEmpty(request.EntryTitle, request.DisplayHint, request.UserName, request.RpId);
		CredentialSubtitle = string.Equals(CredentialTitle, request.UserName, StringComparison.Ordinal)
			? "" : request.UserName;
		CredentialDatabase = request.DatabaseName ?? "";
		CredentialLetter = LetterTile.Letter(CredentialTitle);
		CredentialTileBrush = LetterTile.Brush(CredentialTitle);
		CredentialIcon = IconImage.FromBase64(request.Icon);
	}

	private static string FirstNonEmpty(params string?[] candidates)
	{
		foreach (string? candidate in candidates)
		{
			if (!string.IsNullOrWhiteSpace(candidate)) return candidate;
		}
		return "";
	}
}
