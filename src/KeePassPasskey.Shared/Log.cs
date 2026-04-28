using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace KeePassPasskey.Shared
{
    /// <summary>
    /// Appends timestamped lines to a log file.
    /// Must be initialised once via <see cref="Configure"/> before use;
    /// log calls before that are silently dropped.
    /// </summary>
    public static class Log
    {
        private static string _logFilePath;
        private static string _bakPath;
        private static LogLevel _minLevel = LogLevel.Info;

        private static readonly object _lock = new object();
        private const long MaxLogBytes = 1 * 1024 * 1024; // 1 MB

        public static LogLevel MinLevel => _minLevel;
        public static string LogFilePath => _logFilePath;
        public static string LogDir => _logFilePath != null ? Path.GetDirectoryName(_logFilePath) : null;

        /// <summary>
        /// Sets the log file path and minimum level. Creates the directory if needed.
        /// </summary>
        public static void Configure(string logFilePath, LogLevel minLevel = LogLevel.Info)
        {
            _logFilePath = logFilePath;
            _bakPath = logFilePath + ".bak";
            _minLevel = minLevel;
            Directory.CreateDirectory(Path.GetDirectoryName(logFilePath));
        }

        public static void Debug(string message, [CallerMemberName] string member = "") => Append(LogLevel.Debug, "DEBUG", member, message);
        public static void Info(string message, [CallerMemberName] string member = "") => Append(LogLevel.Info, "INFO ", member, message);
        public static void Warn(string message, [CallerMemberName] string member = "") => Append(LogLevel.Warn, "WARN ", member, message);
        public static void Error(string message, [CallerMemberName] string member = "") => Append(LogLevel.Error, "ERROR", member, message);

        private static void Append(LogLevel level, string label, string member, string message)
        {
            if (level < _minLevel || _logFilePath == null)
                return;

            string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{label}] {member}: {message}";
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_logFilePath) && new FileInfo(_logFilePath).Length >= MaxLogBytes)
                    {
                        // File.Move overload with overwrite is not available in .NET Framework 4.8
                        if (File.Exists(_bakPath)) File.Delete(_bakPath);
                        File.Move(_logFilePath, _bakPath);
                    }
                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
                catch
                {
                    // Logging must never throw.
                }
            }
        }
    }
}
