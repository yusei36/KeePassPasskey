// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskey.Ipc;

/// <summary>
/// Named pipe server that listens on \\.\pipe\ + <see cref="PipeConstants.PipeName"/>.
/// Each connection is handled on a thread pool thread.
/// Messages are length-prefixed: [4-byte LE uint32 length][UTF-8 JSON body].
/// </summary>
internal sealed class PipeServer : IDisposable
{
	private const int MaxInstances = 4;
	// A complete request or response must transfer within this window, or the connection is
	// dropped. Bounds slow/stalled clients holding a thread and a pipe instance open (slowloris).
	private const int MessageTimeoutMs = 10000;

	private readonly RequestHandler _handler;
	private volatile bool _running;
	private Thread _listenThread;
	private NamedPipeServerStream _firstPipe;

	internal PipeServer(RequestHandler handler)
	{
		_handler = handler;
	}

	/// <summary>
	/// Claims the pipe name and starts listening. Returns false if the name is already in use
	/// (possible pipe-name squatting), in which case the server serves no requests.
	/// </summary>
	internal bool Start()
	{
		// First instance uses FILE_FLAG_FIRST_PIPE_INSTANCE, so an existing squatter is detected here.
		try
		{
			_firstPipe = CreatePipe(firstInstance: true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == ERROR_ACCESS_DENIED)
		{
			Log.Error($"Pipe name '{PipeConstants.PipeName}' is already in use by another process. " +
					  "Refusing to serve passkey requests (possible pipe-name squatting). " +
					  "Close the other process and restart KeePass.");
			return false;
		}
		catch (Exception ex)
		{
			Log.Error($"Failed to create named pipe: {ex.Message}");
			return false;
		}

		_running = true;
		_listenThread = new Thread(ListenLoop) { IsBackground = true, Name = "KeePass-Passkey-PipeServer" };
		_listenThread.Start();
		return true;
	}

	internal void Stop()
	{
		_running = false;
		// Wake up the listener by connecting a dummy client
		try
		{
			using (var dummy = new NamedPipeClientStream(".", PipeConstants.PipeName, PipeDirection.Out))
				dummy.Connect(100);
		}
		catch { }
	}

	public void Dispose() => Stop();

	private void ListenLoop()
	{
		while (_running)
		{
			NamedPipeServerStream pipe = null;
			try
			{
				// Reuse the instance claimed in Start() for the first iteration, then create more.
				pipe = Interlocked.Exchange(ref _firstPipe, null) ?? CreatePipe(firstInstance: false);

				pipe.WaitForConnection();

				if (!_running)
				{
					pipe.Dispose();
					break;
				}

				// Hand off to thread pool
				var connectedPipe = pipe;
				pipe = null;
				_ = Task.Run(() => HandleConnection(connectedPipe));
			}
			catch (Exception) when (!_running)
			{
				// Expected on shutdown
				pipe?.Dispose();
				break;
			}
			catch (Exception)
			{
				pipe?.Dispose();
				// Brief pause to avoid tight loop on persistent errors
				Thread.Sleep(500);
			}
		}
	}

	private async Task HandleConnection(NamedPipeServerStream pipe)
	{
		try
		{
			using (pipe)
			{
				// Verify the connecting client before processing any requests
				if (!ClientVerifier.VerifyClient(pipe.SafePipeHandle, out string reason))
				{
					Log.Warn($"Client verification failed: {reason}");
					return;
				}

				while (pipe.IsConnected)
				{
					string requestJson;
					using (var cts = new CancellationTokenSource(MessageTimeoutMs))
						requestJson = await ReadMessage(pipe, cts.Token);
					if (requestJson == null) break;

					var responseJson = _handler.Handle(requestJson);

					using (var cts = new CancellationTokenSource(MessageTimeoutMs))
						await WriteMessage(pipe, responseJson, cts.Token);
				}
			}
		}
		catch (OperationCanceledException)
		{
			Log.Warn("Connection dropped: message timed out");
		}
		catch (Exception ex)
		{
			Log.Error($"Unexpected error: {ex.Message}");
		}
	}

	private static async Task<string> ReadMessage(Stream stream, CancellationToken ct)
	{
		// Read 4-byte length prefix (little-endian)
		var lenBuf = new byte[4];
		if (!await ReadExact(stream, lenBuf, 4, ct)) return null;
		var length = BitConverter.ToUInt32(lenBuf, 0);
		if (length == 0 || length > 1024 * 1024) return null; // sanity check: max 1 MB

		var buf = new byte[length];
		if (!await ReadExact(stream, buf, (int)length, ct)) return null;
		return Encoding.UTF8.GetString(buf);
	}

	private static async Task WriteMessage(Stream stream, string json, CancellationToken ct)
	{
		var body = Encoding.UTF8.GetBytes(json);
		var lenBuf = BitConverter.GetBytes((uint)body.Length);
		await stream.WriteAsync(lenBuf, 0, 4, ct);
		await stream.WriteAsync(body, 0, body.Length, ct);
		await stream.FlushAsync(ct);
	}

	private static async Task<bool> ReadExact(Stream stream, byte[] buf, int count, CancellationToken ct)
	{
		var offset = 0;
		while (offset < count)
		{
			var read = await stream.ReadAsync(buf, offset, count - offset, ct);
			if (read <= 0) return false;
			offset += read;
		}
		return true;
	}

	// The managed PipeOptions enum lacks FILE_FLAG_FIRST_PIPE_INSTANCE on .NET Framework.
	private static NamedPipeServerStream CreatePipe(bool firstInstance)
	{
		uint openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
		if (firstInstance)
			openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

		GCHandle sdPin = default;
		IntPtr pSecAttrs = IntPtr.Zero;
		try
		{
			IntPtr lpSecurityAttributes = IntPtr.Zero;
			if (_securityDescriptor != null)
			{
				sdPin = GCHandle.Alloc(_securityDescriptor, GCHandleType.Pinned);
				var sa = new SECURITY_ATTRIBUTES
				{
					nLength = (uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
					lpSecurityDescriptor = sdPin.AddrOfPinnedObject(),
					bInheritHandle = false,
				};
				pSecAttrs = Marshal.AllocHGlobal((int)sa.nLength);
				Marshal.StructureToPtr(sa, pSecAttrs, false);
				lpSecurityAttributes = pSecAttrs;
			}

			SafePipeHandle handle = CreateNamedPipe(
				@"\\.\pipe\" + PipeConstants.PipeName,
				openMode,
				PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
				(uint)MaxInstances,
				0, 0, 0,
				lpSecurityAttributes);

			if (handle.IsInvalid)
				throw new Win32Exception(Marshal.GetLastWin32Error());

			return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
		}
		finally
		{
			if (pSecAttrs != IntPtr.Zero) Marshal.FreeHGlobal(pSecAttrs);
			if (sdPin.IsAllocated) sdPin.Free();
		}
	}

	// Self-relative security descriptor limiting the pipe to the current user and SYSTEM (no Everyone/anonymous)
	// with a medium-integrity mandatory label so lower-integrity processes
	// cannot connect. Null falls back to the default ACL.
	private static readonly byte[] _securityDescriptor = BuildSecurityDescriptor();

	private static byte[] BuildSecurityDescriptor()
	{
		try
		{
			string userSid = WindowsIdentity.GetCurrent().User.Value;
			// D: full control to the user and SYSTEM. S: medium label, deny read/write-up from below.
			string sddl = $"D:(A;;GA;;;{userSid})(A;;GA;;;SY)S:(ML;;NRNW;;;ME)";
			var rsd = new RawSecurityDescriptor(sddl);
			var bytes = new byte[rsd.BinaryLength];
			rsd.GetBinaryForm(bytes, 0);
			return bytes;
		}
		catch (Exception ex)
		{
			Log.Warn($"Could not build pipe security descriptor, using default ACL: {ex.Message}");
			return null;
		}
	}

	#region Native methods

	private const uint PIPE_ACCESS_DUPLEX = 0x00000003;
	private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
	private const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
	private const uint PIPE_TYPE_BYTE = 0x0;
	private const uint PIPE_READMODE_BYTE = 0x0;
	private const uint PIPE_WAIT = 0x0;
	private const int ERROR_ACCESS_DENIED = 5;

	[StructLayout(LayoutKind.Sequential)]
	private struct SECURITY_ATTRIBUTES
	{
		public uint nLength;
		public IntPtr lpSecurityDescriptor;
		[MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
	}

	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	private static extern SafePipeHandle CreateNamedPipe(
		string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances,
		uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

	#endregion
}
