using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Interop;

/// <summary>
/// Hand-rolled P/Invoke for Win32 APIs used by the COM server host.
/// </summary>
internal static class Win32Native
{

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern int AttachConsole(uint dwProcessId);
    internal const uint ATTACH_PARENT_PROCESS = unchecked((uint)-1);

    [DllImport("ole32.dll")]
    internal static extern int CoRegisterClassObject(
        in Guid rclsid,
        nint pUnk,
        uint dwClsContext,
        uint flags,
        out uint lpdwRegister);

    [DllImport("ole32.dll")]
    internal static extern int CoRevokeClassObject(uint dwRegister);

    internal const uint CLSCTX_LOCAL_SERVER = 0x4;
    internal const uint REGCLS_MULTIPLEUSE = 1;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MSG
    {
        public nint hwnd;
        public uint message;
        public nuint wParam;
        public nint lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll")]
    internal static extern int GetMessage(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    internal static extern bool TranslateMessage(in MSG lpMsg);

    [DllImport("user32.dll")]
    internal static extern nint DispatchMessage(in MSG lpMsg);

    [DllImport("user32.dll")]
    internal static extern void PostQuitMessage(int nExitCode);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool PostThreadMessage(uint idThread, uint Msg, nuint wParam, nint lParam);

    internal const uint WM_QUIT = 0x0012;

    [DllImport("kernel32.dll")]
    internal static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    internal static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll")]
    internal static extern bool ShowWindow(nint hWnd, int nCmdShow);

    internal const int SW_RESTORE = 9;
}
