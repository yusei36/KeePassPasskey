using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace KeePassPasskeyProvider.Util;

/// <summary>
/// Appends timestamped lines to %TEMP%\PasskeyProvider.log,
/// matching the C++ log format so existing troubleshooting workflows still work.
/// Only active in DEBUG builds; calls are eliminated by the compiler in Release.
/// </summary>
internal static class Log
{
    private static readonly string LogPath =
        Path.Combine(Path.GetTempPath(), "PasskeyProvider.log");

    private static readonly string BakPath = LogPath + ".bak";

    private const long MaxLogBytes = 1 * 1024 * 1024; // 1 MB

    private static readonly object _lock = new();

    [Conditional("DEBUG")]
    public static void Info(string message, [CallerMemberName] string member = "") => Append("INFO ", member, message);
    public static void Warn(string message, [CallerMemberName] string member = "") => Append("WARN ", member, message);
    public static void Error(string message, [CallerMemberName] string member = "") => Append("ERROR", member, message);

    private static void Append(string level, string member, string message)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {member}: {message}";
        lock (_lock)
        {
            try
            {
                if (File.Exists(LogPath) && new FileInfo(LogPath).Length >= MaxLogBytes)
                    File.Move(LogPath, BakPath, overwrite: true);

                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
            catch
            {
                // Logging must never throw.
            }
        }
    }
}
