// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskey.Ipc
{
    /// <summary>
    /// Named pipe server that listens on \\.\pipe\ + <see cref="PipeConstants.PipeName"/>.
    /// Each connection is handled on a thread pool thread.
    /// Messages are length-prefixed: [4-byte LE uint32 length][UTF-8 JSON body].
    /// </summary>
    internal sealed class PipeServer : IDisposable
    {
        private const int MaxInstances = 4;

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
                    ThreadPool.QueueUserWorkItem(_ => HandleConnection(connectedPipe));
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

        private void HandleConnection(NamedPipeServerStream pipe)
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
                        var requestJson = ReadMessage(pipe);
                        if (requestJson == null) break;

                        var responseJson = _handler.Handle(requestJson);
                        WriteMessage(pipe, responseJson);
                    }
                }
            }
            catch(Exception ex)
            {
                Log.Error($"Unexpected error: {ex.Message}");
            }
        }

        private static string ReadMessage(Stream stream)
        {
            // Read 4-byte length prefix (little-endian)
            var lenBuf = new byte[4];
            if (!ReadExact(stream, lenBuf, 4)) return null;
            var length = BitConverter.ToUInt32(lenBuf, 0);
            if (length == 0 || length > 1024 * 1024) return null; // sanity check: max 1 MB

            var buf = new byte[length];
            if (!ReadExact(stream, buf, (int)length)) return null;
            return Encoding.UTF8.GetString(buf);
        }

        private static void WriteMessage(Stream stream, string json)
        {
            var body = Encoding.UTF8.GetBytes(json);
            var lenBuf = BitConverter.GetBytes((uint)body.Length);
            stream.Write(lenBuf, 0, 4);
            stream.Write(body, 0, body.Length);
            stream.Flush();
        }

        private static bool ReadExact(Stream stream, byte[] buf, int count)
        {
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(buf, offset, count - offset);
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

            SafePipeHandle handle = CreateNamedPipe(
                @"\\.\pipe\" + PipeConstants.PipeName,
                openMode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                (uint)MaxInstances,
                0, 0, 0,
                IntPtr.Zero);

            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }

        #region Native methods

        private const uint PIPE_ACCESS_DUPLEX = 0x00000003;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
        private const uint PIPE_TYPE_BYTE = 0x0;
        private const uint PIPE_READMODE_BYTE = 0x0;
        private const uint PIPE_WAIT = 0x0;
        private const int ERROR_ACCESS_DENIED = 5;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafePipeHandle CreateNamedPipe(
            string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances,
            uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        #endregion
    }
}
