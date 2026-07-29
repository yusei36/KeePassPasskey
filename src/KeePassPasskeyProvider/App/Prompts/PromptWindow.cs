// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Controls;
using Avalonia.Input;
using KeePassPasskeyProvider.App.ViewModel;

namespace KeePassPasskeyProvider.App.Prompts;

/// <summary>
/// Base for the ceremony prompts. Closing without confirming always means cancelled, which covers
/// the close button, Escape and the countdown alike.
/// </summary>
public abstract class PromptWindow : Window
{
	private PromptViewModelBase? _viewModel;

	protected void Attach(PromptViewModelBase viewModel)
	{
		_viewModel = viewModel;
		DataContext = viewModel;
		viewModel.CloseRequested += OnCloseRequested;
	}

	protected override void OnOpened(EventArgs e)
	{
		base.OnOpened(e);
		_viewModel?.StartCountdown();
	}

	protected override void OnKeyDown(KeyEventArgs e)
	{
		if (e.Key == Key.Escape)
		{
			e.Handled = true;
			Close();
			return;
		}

		if (e.Key == Key.Enter && _viewModel is { CanConfirm: true } vm)
		{
			e.Handled = true;
			vm.ConfirmCommand.Execute(null);
			return;
		}

		base.OnKeyDown(e);
	}

	protected override void OnClosed(EventArgs e)
	{
		if (_viewModel is { } vm)
		{
			vm.CloseRequested -= OnCloseRequested;
			vm.Dispose();
		}
		base.OnClosed(e);
	}

	private void OnCloseRequested(object? sender, EventArgs e) => Close();
}
