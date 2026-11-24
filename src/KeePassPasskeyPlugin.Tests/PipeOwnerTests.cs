// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO.Pipes;
using System.Security.Principal;
using KeePassPasskey.Ipc;
using KeePassPasskeyShared.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PipeOwnerTests
{
	private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

	[Fact]
	public void IsAccepted_CurrentUser()
	{
		Assert.True(PipeOwner.IsAccepted(CurrentUser));
	}

	[Theory]
	[InlineData("S-1-5-21-1111111111-2222222222-3333333333-1001")] // another account
	[InlineData("S-1-1-0")]                                         // Everyone
	[InlineData("S-1-5-18")]                                        // SYSTEM
	[InlineData("S-1-5-32-544")]                                    // Administrators
	public void IsAccepted_RejectsOtherOwners(string sid)
	{
		Assert.False(PipeOwner.IsAccepted(new SecurityIdentifier(sid)));
	}

	[Fact]
	public void Get_ReturnsCurrentUser_ForThePluginsPipe()
	{
		string legacy = "kpp-test-" + Guid.NewGuid().ToString("N");
		string perUser = "kpp-test-" + Guid.NewGuid().ToString("N");
		var server = new PipeServer(null, legacy, perUser);
		try
		{
			Assert.True(server.Start());
			using (var client = new NamedPipeClientStream(".", perUser, PipeDirection.InOut))
			{
				client.Connect(2000);
				var owner = PipeOwner.Get(client.SafePipeHandle, out string error);
				Assert.Null(error);
				Assert.Equal(CurrentUser, owner);
			}
		}
		finally
		{
			server.Stop();
		}
	}
}
