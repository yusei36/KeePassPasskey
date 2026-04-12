using System.IO.Pipes;
using System.Text;
using KeePassPasskey.Shared;
using KeePassPasskeyProvider.Util;
using Newtonsoft.Json;

namespace KeePassPasskeyProvider.Ipc;

/// <summary>
/// Synchronous named-pipe client for the KeePass passkey plugin IPC protocol.
/// Wire format: [4-byte LE uint32 length][UTF-8 JSON body]
/// </summary>
internal static class PipeClient
{
    private const string PipeName = "keepass-passkey-provider";
    private const int ConnectTimeoutMs = 2000;
    private const int MaxMessageBytes = 1024 * 1024; // 1 MB sanity limit

    /// <summary>
    /// Sends an IpcRequest to the KeePass plugin and deserializes the response.
    /// Returns false if the pipe is unavailable (KeePass not running / database locked).
    /// </summary>
    public static bool SendRequest(IpcRequest request, out IpcResponse? response)
    {
        response = null;
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
            pipe.Connect(ConnectTimeoutMs);

            string requestJson = JsonConvert.SerializeObject(request);
            byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
            Log.Info($">> {requestJson}");
            WriteMessage(pipe, requestBytes);

            byte[] responseBytes = ReadMessage(pipe);
            string responseJson = Encoding.UTF8.GetString(responseBytes);
            Log.Info($"<< {responseJson}");
            response = JsonConvert.DeserializeObject<IpcResponse>(responseJson);
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            Log.Info($"{ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private static void WriteMessage(PipeStream pipe, byte[] json)
    {
        uint length = (uint)json.Length;
        Span<byte> lenBuf = stackalloc byte[4];
        lenBuf[0] = (byte)(length & 0xFF);
        lenBuf[1] = (byte)((length >> 8) & 0xFF);
        lenBuf[2] = (byte)((length >> 16) & 0xFF);
        lenBuf[3] = (byte)((length >> 24) & 0xFF);
        pipe.Write(lenBuf);
        pipe.Write(json);
        pipe.Flush();
    }

    private static byte[] ReadMessage(PipeStream pipe)
    {
        Span<byte> lenBuf = stackalloc byte[4];
        ReadExact(pipe, lenBuf);
        uint length = (uint)(lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24));

        if (length == 0 || length > MaxMessageBytes)
            throw new IOException($"PipeClient: invalid message length {length}");

        byte[] buf = new byte[length];
        ReadExact(pipe, buf);
        return buf;
    }

    private static void ReadExact(PipeStream pipe, Span<byte> buffer)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int n = pipe.Read(buffer[totalRead..]);
            if (n == 0) throw new IOException("PipeClient: unexpected end of stream");
            totalRead += n;
        }
    }
}
