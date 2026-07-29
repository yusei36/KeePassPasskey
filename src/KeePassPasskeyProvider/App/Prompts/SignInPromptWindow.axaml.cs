// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Prompts;

public partial class SignInPromptWindow : PromptWindow
{
	public SignInPromptWindow() => InitializeComponent();

	internal SignInPromptWindow(SignInPromptViewModel viewModel) : this() => Attach(viewModel);
}
