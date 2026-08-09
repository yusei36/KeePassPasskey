// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia.Threading;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.App.Utils;

/// <summary>
/// Waits on a named event and runs an action on the UI thread each time it is signalled. This is how
/// a second launch of the app reaches the instance that already owns the single-instance mutex.
/// </summary>
internal sealed class NamedEventWatcher : IDisposable
{
	private nint _handle;
	private volatile bool _disposed;

	internal NamedEventWatcher(string name, Action onSignalled)
	{
		_handle = Win32Native.CreateEvent(0, false, false, name);
		if (_handle == 0) return;

		// By value: Dispose clears the field and the loop closes the handle it was given.
		nint handle = _handle;
		_ = Task.Run(async () =>
		{
			while (true)
			{
				uint r = Win32Native.WaitForSingleObject(handle, Win32Native.INFINITE);
				if (_disposed)
				{
					Win32Native.CloseHandle(handle);
					return;
				}
				// Anything but a signal is unrecoverable here, and retrying would spin the thread.
				if (r != Win32Native.WAIT_OBJECT_0)
				{
					Win32Native.CloseHandle(handle);
					return;
				}
				await Dispatcher.UIThread.InvokeAsync(onSignalled);
			}
		});
	}

	public void Dispose()
	{
		if (_disposed) return;
		_disposed = true;

		// Hand ownership to the loop, which closes the handle once this wakes it.
		nint handle = _handle;
		_handle = 0;
		if (handle != 0) Win32Native.SetEvent(handle);
	}
}
