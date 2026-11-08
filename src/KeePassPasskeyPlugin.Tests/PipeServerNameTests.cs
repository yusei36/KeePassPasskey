// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using KeePassPasskey.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PipeServerNameTests
{
	// Private names per test, so a running provider or KeePass on the machine cannot interfere.
	private readonly string _legacy = "kpp-test-" + Guid.NewGuid().ToString("N");
	private readonly string _perUser = "kpp-test-" + Guid.NewGuid().ToString("N");

	[Fact]
	public void Start_ClaimsLegacyName_WhenFree()
	{
		var server = new PipeServer(null, _legacy, _perUser);
		try
		{
			Assert.True(server.Start());
			Assert.True(PipeExists(_legacy));
			Assert.False(PipeExists(_perUser));
		}
		finally
		{
			server.Stop();
		}
	}

	[Theory]
	[InlineData(NamedPipeServerStream.MaxAllowedServerInstances)] // taken, instances left: ERROR_ACCESS_DENIED
	[InlineData(1)]                                                // taken, all instances busy: ERROR_PIPE_BUSY
	public void Start_FallsBackToPerUserName_WhenLegacyNameIsTaken(int ownerMaxInstances)
	{
		// Stands in for the KeePass of another signed-in user holding the legacy name.
		using (new NamedPipeServerStream(_legacy, PipeDirection.InOut, ownerMaxInstances))
		{
			var server = new PipeServer(null, _legacy, _perUser);
			try
			{
				Assert.True(server.Start());
				Assert.True(PipeExists(_perUser));
			}
			finally
			{
				server.Stop();
			}
		}
	}

	private static bool PipeExists(string name)
		=> WaitNamedPipe(@"\\.\pipe\" + name, 1) || Marshal.GetLastWin32Error() != ERROR_FILE_NOT_FOUND;

	private const int ERROR_FILE_NOT_FOUND = 2;

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern bool WaitNamedPipe(string name, uint timeout);
}
