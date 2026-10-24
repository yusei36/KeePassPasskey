// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Refreshes the credential cache when the platform reports a status change, for as long as the
/// app (window or tray) runs. Windows keeps the rows of a switched-off provider and the plugin
/// cannot see the switch, so otherwise the cache only catches up at the next /synccredential. The
/// on-demand COM server cannot host this: it only lives during an operation, which cannot happen
/// while the provider is switched off.
/// </summary>
internal static unsafe class AuthenticatorStatusWatcher
{
	private static uint _registration;
	// The platform hands out 0 as a valid cookie, so the token cannot double as the flag.
	private static int _registered;
	private static int _refreshQueued;

	public static void Start()
	{
		if (Volatile.Read(ref _registered) == 1) return;

		uint token = 0;
		int hr = WebAuthnPluginApi.WebAuthNPluginRegisterStatusChangeCallback(
			&OnStatusChanged, null, PluginConstants.KeePassPasskeyProviderClsid, &token);
		if (hr < HResults.S_OK)
		{
			Log.Warn($"WebAuthNPluginRegisterStatusChangeCallback failed hr=0x{hr:X8}");
			return;
		}

		_registration = token;
		Volatile.Write(ref _registered, 1);
		Log.Info($"watching authenticator status, registration={token}");
	}

	public static void Stop()
	{
		if (Interlocked.Exchange(ref _registered, 0) == 0) return;

		uint token = _registration;
		int hr = WebAuthnPluginApi.WebAuthNPluginUnregisterStatusChangeCallback(&token);
		if (hr < HResults.S_OK)
			Log.Warn($"WebAuthNPluginUnregisterStatusChangeCallback failed hr=0x{hr:X8}");
	}

	/// <summary>
	/// Whether a re-added authenticator keeps its callback registration is undocumented, so a
	/// register cycle re-registers rather than assume.
	/// </summary>
	public static void Restart()
	{
		Stop();
		Start();
	}

	// Runs on a platform thread and must never throw. The work sits in a separate non-inlined
	// method because a JIT-time failure (an unresolvable method, as a stale trimmed runtime once
	// produced) is raised while the caller's frame is compiled, before this try block exists, so
	// only a failure reached through the call below is catchable at all.
	[UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
	private static void OnStatusChanged(void* context)
	{
		try { QueueRefresh(); }
		catch { /* never throw into unmanaged code */ }
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void QueueRefresh()
	{
		// One flip can be reported more than once, so collapse a burst into a single run.
		if (Interlocked.Exchange(ref _refreshQueued, 1) == 1) return;

		ThreadPool.QueueUserWorkItem(static _ =>
		{
			Interlocked.Exchange(ref _refreshQueued, 0);
			try
			{
				Log.Info("authenticator status changed, refreshing the credential cache");
				CredentialCache.Refresh(PluginConstants.KeePassPasskeyProviderClsid);
			}
			catch (Exception ex)
			{
				Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
			}
		});
	}
}
