// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using KeePassPasskeyShared.Ipc;
using Newtonsoft.Json;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class UnlockDatabaseProtocolTests
{
	[Fact]
	public void Request_RoundTripsThroughRequestConverter()
	{
		var json = JsonConvert.SerializeObject(new UnlockDatabaseRequest { ProtocolVersion = PipeConstants.ProtocolVersion });
		var req = JsonConvert.DeserializeObject<PipeRequestBase>(json);
		Assert.IsType<UnlockDatabaseRequest>(req);
	}

	[Fact]
	public void Busy_RoundTrips()
	{
		var json = JsonConvert.SerializeObject(new UnlockDatabaseResponse { Busy = true });
		var response = JsonConvert.DeserializeObject<UnlockDatabaseResponse>(json);
		Assert.NotNull(response);
		Assert.True(response.Busy);
		Assert.False(response.Unlocked);
	}

	[Fact]
	public void ErrorFromOlderPlugin_ReadsAsNotUnlocked()
	{
		// What a plugin that does not know the request answers.
		var json = JsonConvert.SerializeObject(new PipeResponseBase { ErrorCode = PipeErrorCode.InternalError, ErrorMessage = "Failed to parse request" });
		var response = JsonConvert.DeserializeObject<UnlockDatabaseResponse>(json);
		Assert.NotNull(response);
		Assert.False(response.Unlocked);
		Assert.False(response.Busy);
		Assert.Equal(PipeErrorCode.InternalError, response.ErrorCode);
	}
}
