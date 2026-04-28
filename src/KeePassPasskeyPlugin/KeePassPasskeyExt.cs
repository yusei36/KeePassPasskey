using KeePass.Plugins;
using KeePassPasskey.Ipc;
using KeePassPasskey.Storage;
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace KeePassPasskey
{
    /// <summary>
    /// KeePass plugin entry point.
    /// Starts the named pipe server on Initialize() so the native COM server
    /// (KeePassPasskeyProvider.exe) can connect to perform passkey operations.
    /// </summary>
    public sealed class KeePassPasskeyExt : Plugin
    {
        private IPluginHost _host;
        private PipeServer _pipeServer;

        // Loaded once; MemoryStream kept open for GDI+ lifetime requirement.
        private static readonly Image _smallIcon = LoadSmallIcon();

        private static Image LoadSmallIcon()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (Stream raw = asm.GetManifestResourceStream(
                "KeePassPasskey.Resources.plugin-icon.png"))
            {
                var ms = new MemoryStream();
                raw.CopyTo(ms);
                ms.Position = 0;
                return Image.FromStream(ms);
            }
        }

        public override Image SmallIcon => _smallIcon;

        public override string UpdateUrl => "https://keepasspasskey.github.io/version.txt";
        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;

            // Windows 11 24H2 required (build 26100+) for the passkey provider API.
            if (GetRealWindowsBuildNumber() < 26100)
            {
                return false;
            }

            _host = host;

            var storage = new PasskeyEntryStorage(_host);
            var handler = new RequestHandler(_host, storage);
            _pipeServer = new PipeServer(handler, PluginLog);
            _pipeServer.Start();

            return true;
        }

        public override void Terminate()
        {
            _pipeServer?.Stop();
            _pipeServer = null;
        }

        private static readonly string _logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "KeePassPasskeyProvider", "plugin.log");

        private static void PluginLog(string message)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_logPath));
                File.AppendAllText(_logPath,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
            }
            catch { }
        }

        // Environment.OSVersion lies on .NET Framework without a matching manifest — use RtlGetVersion instead.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOEX
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref OSVERSIONINFOEX lpVersionInformation);

        private static uint GetRealWindowsBuildNumber()
        {
            var osvi = new OSVERSIONINFOEX { dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEX)) };
            RtlGetVersion(ref osvi);
            return osvi.dwBuildNumber;
        }
    }
}
