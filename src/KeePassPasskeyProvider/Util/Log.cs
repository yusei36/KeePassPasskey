using System.Diagnostics;

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

    private static readonly object _lock = new();

    [Conditional("DEBUG")]
    public static void Info(string message) => Append("INFO ", message);

    [Conditional("DEBUG")]
    public static void Warn(string message) => Append("WARN ", message);

    [Conditional("DEBUG")]
    public static void Error(string message) => Append("ERROR", message);

    private static void Append(string level, string message)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}";
        lock (_lock)
        {
            try
            {
                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
            catch
            {
                // Logging must never throw.
            }
        }
    }
}
