using KeePass.Plugins;
using KeePassPasskeyPlugin.Ipc;
using KeePassPasskeyPlugin.Storage;
using System;

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

        public override string UpdateUrl =>
            "https://github.com/your-org/PasskeyWin11/raw/main/version.txt";

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
