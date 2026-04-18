using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace KeePassPasskeyProvider.Util;

/// <summary>
/// Appends timestamped lines to %LOCALAPPDATA%\KeePassPasskeyProvider\PasskeyProvider.log -- redirects in msix to: %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\Local\KeePassPasskeyProvider\PasskeyProvider.log
/// <see cref="Info"/> is only active in DEBUG builds; <see cref="Warn"/> and <see cref="Error"/> are always active.
/// </summary>
internal static class Log
{
    // redirects in msix to: %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\Local\KeePassPasskeyProvider
    private static readonly string LogDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     "KeePassPasskeyProvider");

    public static readonly string LogFilePath = Path.Combine(LogDir, "PasskeyProvider.log");

    private static readonly string BakPath = LogFilePath + ".bak";

    static Log() => Directory.CreateDirectory(LogDir);

    private const long MaxLogBytes = 1 * 1024 * 1024; // 1 MB

    private static readonly object _lock = new();

    [Conditional("DEBUG")]
    public static void Debug(string message, [CallerMemberName] string member = "") => Append("DEBUG", member, message);
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
