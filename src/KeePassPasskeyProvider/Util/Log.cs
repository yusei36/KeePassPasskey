using System.Runtime.CompilerServices;

namespace KeePassPasskeyProvider.Util;

/// <summary>
/// Appends timestamped lines to %LOCALAPPDATA%\KeePassPasskeyProvider\PasskeyProvider.log -- redirects in msix to: %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\KeePassPasskeyProvider\PasskeyProvider.log
/// Log level is read from appsettings.json in the same directory; defaults to Info.
/// </summary>
internal static class Log
{
    public static readonly string LogDir = AppSettings.ConfigDir;

    public static readonly string LogFilePath = Path.Combine(LogDir, "PasskeyProvider.log");

    private static readonly string BakPath = LogFilePath + ".bak";

    private static readonly LogLevel _minLevel;

    public static LogLevel MinLevel => _minLevel;

    static Log()
    {
        Directory.CreateDirectory(LogDir);
        _minLevel = AppSettings.Current.LogLevel;
    }

    private const long MaxLogBytes = 1 * 1024 * 1024; // 1 MB

    private static readonly object _lock = new();

    public static void Debug(string message, [CallerMemberName] string member = "") => Append(LogLevel.Debug, "DEBUG", member, message);
    public static void Info(string message, [CallerMemberName] string member = "") => Append(LogLevel.Info, "INFO ", member, message);
    public static void Warn(string message, [CallerMemberName] string member = "") => Append(LogLevel.Warn, "WARN ", member, message);
    public static void Error(string message, [CallerMemberName] string member = "") => Append(LogLevel.Error, "ERROR", member, message);

    private static void Append(LogLevel level, string label, string member, string message)
    {
        if (level < _minLevel)
            return;

        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{label}] {member}: {message}";
        lock (_lock)
        {
            try
            {
                if (File.Exists(LogFilePath) && new FileInfo(LogFilePath).Length >= MaxLogBytes)
                    File.Move(LogFilePath, BakPath, overwrite: true);

                File.AppendAllText(LogFilePath, line + Environment.NewLine);
            }
            catch
            {
                // Logging must never throw.
            }
        }
    }
}
