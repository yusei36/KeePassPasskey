using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PasskeyWinNative.IPC
{
    /// <summary>
    /// Named pipe server that listens on \\.\pipe\keepass-passkey-provider.
    /// Each connection is handled on a thread pool thread.
    /// Messages are length-prefixed: [4-byte LE uint32 length][UTF-8 JSON body].
    /// </summary>
    internal sealed class PipeServer : IDisposable
    {
        private const string PipeName = "keepass-passkey-provider";
        private const int MaxInstances = 4;

        private readonly RequestHandler _handler;
        private volatile bool _running;
        private Thread _listenThread;

        internal PipeServer(RequestHandler handler)
        {
            _handler = handler;
        }

        internal void Start()
        {
            _running = true;
            _listenThread = new Thread(ListenLoop) { IsBackground = true, Name = "KeePass-Passkey-PipeServer" };
            _listenThread.Start();
        }

        internal void Stop()
        {
            _running = false;
            // Wake up the listener by connecting a dummy client
            try
            {
                using (var dummy = new NamedPipeClientStream(".", PipeName, PipeDirection.Out))
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
                    // Grant access to the current user and to ALL APPLICATION PACKAGES
                    // so that the MSIX-packaged COM server (AppContainer process) can connect.
                    var ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule(
                        WindowsIdentity.GetCurrent().User,
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));
                    ps.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier("S-1-15-2-1"), // ALL APPLICATION PACKAGES
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));

                    pipe = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        MaxInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0, 0, ps);

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
                catch (Exception ex) when (!_running)
                {
                    // Expected on shutdown
                    pipe?.Dispose();
                    break;
                }
                catch (Exception ex)
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
                    while (pipe.IsConnected)
                    {
                        var requestJson = ReadMessage(pipe);
                        if (requestJson == null) break;

                        var responseJson = _handler.Handle(requestJson);
                        WriteMessage(pipe, responseJson);
                    }
                }
            }
            catch { }
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
    }
}
