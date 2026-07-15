// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeePassPasskeyShared.Ipc;
using Xunit;

namespace KeePassPasskeyPlugin.Tests;

public class PipeClientMalformedResponseTests
{
	// Unique per test: the real pipe name would collide with a dev KeePass instance.
	private static string NewPipeName() => "keepass-passkey-test-" + Guid.NewGuid().ToString("N");

	// A pipe read can return short; loop until the caller's count is satisfied.
	private static async Task ReadExactly(Stream stream, byte[] buffer, int count, CancellationToken ct)
	{
		int total = 0;
		while (total < count)
		{
			int read = await stream.ReadAsync(buffer, total, count - total, ct).ConfigureAwait(false);
			if (read == 0) throw new EndOfStreamException();
			total += read;
		}
	}

	// Serves one canned reply so PipeClient.Send can be driven end to end.
	private static Task ServeOnce(string pipeName, string responseJson, CancellationToken ct)
	{
		return Task.Run(async () =>
		{
			using (var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
									PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
			{
				await server.WaitForConnectionAsync(ct);

				var lenBuf = new byte[4];
				await ReadExactly(server, lenBuf, 4, ct);
				int len = lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24);
				await ReadExactly(server, new byte[len], len, ct);

				var body = Encoding.UTF8.GetBytes(responseJson);
				var outLen = BitConverter.GetBytes((uint)body.Length);
				await server.WriteAsync(outLen, 0, 4, ct);
				await server.WriteAsync(body, 0, body.Length, ct);
				await server.FlushAsync(ct);
				server.WaitForPipeDrain();
			}
		}, ct);
	}

	[Fact]
	public async Task UnknownErrorCode_YieldsInternalError_InsteadOfThrowing()
	{
		using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
		{
			var pipeName = NewPipeName();
			var server = ServeOnce(pipeName, @"{""type"":""save_settings"",""errorCode"":""some_future_code""}", cts.Token);

			var response = await Task.Run(() => new PipeClient(pipeName: pipeName).SaveSettings(new SaveSettingsRequest()));

			Assert.NotNull(response);
			Assert.Equal(PipeErrorCode.InternalError, response!.ErrorCode);
			Assert.Contains("incompatible", response.ErrorMessage, StringComparison.OrdinalIgnoreCase);
			await server;
		}
	}

	[Fact]
	public async Task MalformedPing_IsTreatedAsNotReady()
	{
		using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
		{
			var pipeName = NewPipeName();
			var server = ServeOnce(pipeName, @"{""type"":""ping"",""status"":""nonsense_status""}", cts.Token);

			var response = await Task.Run(() => new PipeClient(pipeName: pipeName).Ping());

			Assert.NotNull(response);
			Assert.Null(response!.Status);
			Assert.Equal(PipeErrorCode.InternalError, response.ErrorCode);
			await server;
		}
	}
}
