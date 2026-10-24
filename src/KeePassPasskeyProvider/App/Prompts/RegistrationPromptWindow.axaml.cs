// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Prompts;

public partial class RegistrationPromptWindow : PromptWindow
{
	public RegistrationPromptWindow() => InitializeComponent();

	internal RegistrationPromptWindow(RegistrationPromptViewModel viewModel) : this() => Attach(viewModel);
}
