namespace PasskeyProviderManaged.Util;

/// <summary>
/// Appends timestamped lines to %TEMP%\PasskeyProvider.log,
/// matching the C++ log format so existing troubleshooting workflows still work.
/// </summary>
internal static class Log
{
    private static readonly string LogPath =
        Path.Combine(Path.GetTempPath(), "PasskeyProvider.log");

    private static readonly object _lock = new();

    public static void Write(string message)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
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
