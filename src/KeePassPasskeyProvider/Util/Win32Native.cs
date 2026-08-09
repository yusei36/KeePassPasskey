// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Util;

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

	[StructLayout(LayoutKind.Sequential)]
	internal struct POINT
	{
		public int X;
		public int Y;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct RECT
	{
		public int Left;
		public int Top;
		public int Right;
		public int Bottom;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct MONITORINFO
	{
		public int cbSize;
		public RECT rcMonitor;
		public RECT rcWork;
		public uint dwFlags;
	}

	[DllImport("user32.dll")]
	internal static extern bool GetCursorPos(out POINT lpPoint);

	[DllImport("user32.dll")]
	internal static extern nint MonitorFromWindow(nint hWnd, uint dwFlags);

	[DllImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
	internal static extern bool GetMonitorInfo(nint hMonitor, ref MONITORINFO lpmi);

	internal const uint MONITOR_DEFAULTTONEAREST = 2;

	[DllImport("user32.dll")]
	internal static extern nint GetForegroundWindow();

	[DllImport("user32.dll")]
	internal static extern bool SetForegroundWindow(nint hWnd);

	[DllImport("user32.dll")]
	internal static extern bool AllowSetForegroundWindow(int dwProcessId);

	[DllImport("user32.dll")]
	internal static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

	[DllImport("user32.dll")]
	internal static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

	[DllImport("user32.dll")]
	internal static extern bool ShowWindow(nint hWnd, int nCmdShow);

	internal const int SW_HIDE = 0;
	internal const int SW_SHOW = 5;
	internal const int SW_RESTORE = 9;

	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	internal static extern nint CreateEvent(nint lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	internal static extern nint OpenEvent(uint dwDesiredAccess, bool bInheritHandle, string lpName);

	[DllImport("kernel32.dll")]
	internal static extern bool SetEvent(nint hEvent);

	[DllImport("kernel32.dll")]
	internal static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

	[DllImport("kernel32.dll")]
	internal static extern bool CloseHandle(nint hObject);

	[DllImport("user32.dll")]
	internal static extern uint GetDoubleClickTime();

	[DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
	internal static extern nint SetWindowLongPtr(nint hWnd, int nIndex, nint dwNewLong);

	internal const int GWLP_HWNDPARENT = -8;

	[DllImport("user32.dll")]
	internal static extern bool IsWindow(nint hWnd);

	[DllImport("dwmapi.dll")]
	internal static extern int DwmSetWindowAttribute(nint hwnd, uint dwAttribute, in uint pvAttribute, uint cbAttribute);

	internal const uint DWMWA_CLOAK = 13;
	internal const uint DWMWA_BORDER_COLOR = 34;
	internal const uint DWMWA_COLOR_NONE = 0xFFFFFFFE;

	internal const uint EVENT_MODIFY_STATE = 0x0002;
	internal const uint WAIT_OBJECT_0 = 0;
	internal const uint INFINITE = unchecked((uint)-1);
}
