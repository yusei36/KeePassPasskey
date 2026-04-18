using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using Newtonsoft.Json;

namespace KeePassPasskey.Shared.Ipc
{
    /// <summary>
    /// Synchronous named-pipe client for the KeePass passkey plugin IPC protocol.
    /// Wire format: [4-byte LE uint32 length][UTF-8 JSON body]
    /// Returns null when the pipe is unavailable (KeePass not running).
    /// </summary>
    public sealed class PipeClient
    {
        private const int ConnectTimeoutMs = 2000;
        private const int MaxMessageBytes = 1024 * 1024; // 1 MB sanity limit

        private readonly Action<string> _logger;

        public PipeClient(Action<string> logger = null)
        {
            _logger = logger;
        }

        public PingResponse Ping()
            => Send<PingResponse>(new PingRequest());

        public GetCredentialsResponse GetCredentials(GetCredentialsRequest request)
            => Send<GetCredentialsResponse>(request);

        public MakeCredentialResponse MakeCredential(MakeCredentialRequest request)
            => Send<MakeCredentialResponse>(request);

        public GetAssertionResponse GetAssertion(GetAssertionRequest request)
            => Send<GetAssertionResponse>(request);

        public CancelResponse Cancel()
            => Send<CancelResponse>(new CancelRequest());

        private TResponse Send<TResponse>(PipeRequestBase request) where TResponse : PipeResponseBase
        {
            try
            {
                using (var pipe = new NamedPipeClientStream(".", PipeConstants.PipeName, PipeDirection.InOut))
                {
                    pipe.Connect(ConnectTimeoutMs);

                    string requestJson = JsonConvert.SerializeObject(request);
                    byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
                    _logger?.Invoke($">> {requestJson}");
                    WriteMessage(pipe, requestBytes);

                    byte[] responseBytes = ReadMessage(pipe);
                    string responseJson = Encoding.UTF8.GetString(responseBytes);
                    _logger?.Invoke($"<< {responseJson}");
                    return JsonConvert.DeserializeObject<PipeResponseBase>(responseJson) as TResponse;
                }
            }
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is UnauthorizedAccessException)
            {
                _logger?.Invoke($"{ex.GetType().Name}: {ex.Message}");
                return null;
            }
        }

        private static void WriteMessage(NamedPipeClientStream pipe, byte[] json)
        {
            uint length = (uint)json.Length;
            byte[] lenBuf = new byte[4];
            lenBuf[0] = (byte)(length & 0xFF);
            lenBuf[1] = (byte)((length >> 8) & 0xFF);
            lenBuf[2] = (byte)((length >> 16) & 0xFF);
            lenBuf[3] = (byte)((length >> 24) & 0xFF);
            pipe.Write(lenBuf, 0, 4);
            pipe.Write(json, 0, json.Length);
            pipe.Flush();
        }

        private static byte[] ReadMessage(NamedPipeClientStream pipe)
        {
            byte[] lenBuf = new byte[4];
            ReadExact(pipe, lenBuf, 4);
            uint length = (uint)(lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24));

            if (length == 0 || length > MaxMessageBytes)
                throw new IOException($"PipeClient: invalid message length {length}");

            byte[] buf = new byte[length];
            ReadExact(pipe, buf, (int)length);
            return buf;
        }

        private static void ReadExact(NamedPipeClientStream pipe, byte[] buffer, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int n = pipe.Read(buffer, totalRead, count - totalRead);
                if (n == 0) throw new IOException("PipeClient: unexpected end of stream");
                totalRead += n;
            }
        }
    }
}
