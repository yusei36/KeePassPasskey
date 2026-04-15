using KeePass.Plugins;
using KeePassPasskeyPlugin.Ipc;
using KeePassPasskeyPlugin.Storage;
using System;
using System.Drawing;
using System.IO;
using System.Reflection;

namespace KeePassPasskeyPlugin
{
    /// <summary>
    /// KeePass plugin entry point.
    /// Starts the named pipe server on Initialize() so the native COM server
    /// (KeePassPasskeyProvider.exe) can connect to perform passkey operations.
    /// </summary>
    public sealed class KeePassPasskeyPluginExt : Plugin
    {
        private IPluginHost _host;
        private PipeServer _pipeServer;

        // Loaded once; MemoryStream kept open for GDI+ lifetime requirement.
        private static readonly Image _smallIcon = LoadSmallIcon();

        private static Image LoadSmallIcon()
        {
            var asm = Assembly.GetExecutingAssembly();
            using (Stream raw = asm.GetManifestResourceStream(
                "KeePassPasskeyPlugin.Resources.plugin-icon.png"))
            {
                var ms = new MemoryStream();
                raw.CopyTo(ms);
                ms.Position = 0;
                return Image.FromStream(ms);
            }
        }

        public override Image SmallIcon => _smallIcon;

        public override string UpdateUrl =>
            "https://github.com/your-org/KeePassPasskey/raw/main/version.txt";
        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            _host = host;

            var storage = new PasskeyEntryStorage(_host);
            var handler = new RequestHandler(_host, storage);
            _pipeServer = new PipeServer(handler);
            _pipeServer.Start();

            return true;
        }

        public override void Terminate()
        {
            _pipeServer?.Stop();
            _pipeServer = null;
        }
    }
}
