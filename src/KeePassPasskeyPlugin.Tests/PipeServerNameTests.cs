// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using KeePassPasskey.Ipc;
using KeePassPasskeyShared.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PipeServerNameTests
{
	[Fact]
	public void Start_ClaimsLegacyName_WhenFree()
	{
		WaitUntilGone(PipeConstants.LegacyPipeName);
		var server = new PipeServer(null);
		try
		{
			Assert.True(server.Start());
			Assert.True(PipeExists(PipeConstants.LegacyPipeName));
			Assert.False(PipeExists(PipeConstants.PipeName));
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
		WaitUntilGone(PipeConstants.LegacyPipeName);
		// Stands in for the KeePass of another signed-in user holding the legacy name.
		using (new NamedPipeServerStream(PipeConstants.LegacyPipeName, PipeDirection.InOut, ownerMaxInstances))
		{
			var server = new PipeServer(null);
			try
			{
				Assert.True(server.Start());
				Assert.True(PipeExists(PipeConstants.PipeName));
			}
			finally
			{
				server.Stop();
			}
		}
	}

	private static void WaitUntilGone(string name)
	{
		var elapsed = Stopwatch.StartNew();
		while (PipeExists(name) && elapsed.ElapsedMilliseconds < 3000)
			Thread.Sleep(50);
	}

	private static bool PipeExists(string name)
		=> WaitNamedPipe(@"\\.\pipe\" + name, 1) || Marshal.GetLastWin32Error() != ERROR_FILE_NOT_FOUND;

	private const int ERROR_FILE_NOT_FOUND = 2;

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern bool WaitNamedPipe(string name, uint timeout);
}
