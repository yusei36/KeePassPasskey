// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassPasskey.Ipc;
using KeePassPasskey.Storage;
using KeePassPasskey.UI;
using KeePassPasskeyShared;

namespace KeePassPasskey;

/// <summary>
/// KeePass plugin entry point.
/// Starts the named pipe server on Initialize() so the native COM server
/// (KeePassPasskeyProvider.exe) can connect to perform passkey operations.
/// </summary>
public sealed class KeePassPasskeyExt : Plugin
{
	private IPluginHost _host;
	private PipeServer _pipeServer;
	private PasskeySyncTrigger _syncTrigger;
	private EntryMenuController _entryMenu;

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

		var settingsStorage = new SettingsStorage(host);
		var initialSettings = settingsStorage.Load();
		Log.Configure(Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
			"KeePassPasskeyProvider", "Plugin.log"),
			initialSettings.LogLevel);

		// Windows 11 24H2 required (build 26100+) for the passkey provider API.
		var buildVersion = GetRealWindowsBuildNumber();
		if (buildVersion < 26100)
		{
			Log.Error("Unsupported Windows version: build = " + buildVersion + " but plugin requires build >= 26100 (Windows 11 24H2)");
			return false;
		}

		_host = host;

		try
		{
			var passkeyStorage = new PasskeyEntryStorage(_host, settingsStorage);

			// Entry context-menu cut/paste actions for moving a passkey between entries.
			_entryMenu = new EntryMenuController(_host, passkeyStorage);

			var handler = new RequestHandler(_host, passkeyStorage, settingsStorage);
			_pipeServer = new PipeServer(handler);
			if (_pipeServer.Start())
			{
				// Drive Windows credential-cache sync from KeePass database/passkey events.
				_syncTrigger = new PasskeySyncTrigger(_host, passkeyStorage, settingsStorage);
			}
			else
			{
				// Pipe name held by another process; skip sync (it would feed the squatter) and warn.
				KeePassLib.Utility.MessageService.ShowWarning(
					"KeePassPasskey could not claim its named pipe.",
					"Another process is already using the passkey pipe name. Passkey operations are disabled until you close that process and restart KeePass.");
			}
		}
		catch (Exception ex)
		{
			Log.Error("Failed to start pipe server: " + ex.Message);
			throw;
		}

		return true;
	}

	public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
	{
		if (t != PluginMenuType.Entry) return null;
		return _entryMenu?.GetEntryMenuItem();
	}

	public override void Terminate()
	{
		_entryMenu?.Dispose();
		_entryMenu = null;
		_syncTrigger?.Dispose();
		_syncTrigger = null;
		_pipeServer?.Stop();
		_pipeServer = null;
	}

	// Environment.OSVersion lies on .NET Framework without a matching manifest - use RtlGetVersion instead.
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
