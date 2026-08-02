// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using KeePassPasskeyShared;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Synchronises KeePass credentials with the Windows platform autofill cache.
/// Uses diff-based add/remove to minimise API calls.
/// </summary>
internal static unsafe class CredentialCache
{
	private static readonly SemaphoreSlim _syncGate = new SemaphoreSlim(1, 1);

	// Cross-process gate: /synccredential one-shots and the management app's save-time sync/clear
	// can run in separate processes, so serialize all cache writes via a named mutex.
	private static Mutex? AcquireCrossProcessLock()
	{
		var m = new Mutex(false, PluginConstants.CacheSyncMutexName);
		try
		{
			if (!m.WaitOne(TimeSpan.FromSeconds(15)))
			{
				m.Dispose();
				return null;
			}
		}
		catch (AbandonedMutexException)
		{
			// A process died holding the mutex; we now own it. Any partial write is corrected by
			// the next full sync/clear.
		}
		return m;
	}

	private static void ReleaseCrossProcessLock(Mutex? m)
	{
		if (m == null) return;
		try { m.ReleaseMutex(); } catch { /* not held */ }
		m.Dispose();
	}

	/// <summary>
	/// Query KeePass for all passkeys and push changes to the Windows cache.
	/// Returns true if KeePass was reached (sync applied), false otherwise.
	/// </summary>
	public static bool SyncToWindowsCache(Guid pluginClsid)
	{
		_syncGate.Wait();
		Mutex? crossProcess = AcquireCrossProcessLock();
		if (crossProcess == null)
		{
			_syncGate.Release();
			Log.Warn("could not acquire cross-process cache lock, skipping sync");
			return false;
		}
		try
		{
			return SyncToCredentialCache(pluginClsid);
		}
		catch (Exception ex)
		{
			Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
			return false;
		}
		finally
		{
			ReleaseCrossProcessLock(crossProcess);
			_syncGate.Release();
		}
	}

	/// <summary>
	/// Removes every credential from the Windows autofill cache. Returns false if the platform
	/// refused. The cache repopulates on the next sync (database open/save or a passkey change).
	/// </summary>
	public static bool ClearWindowsCache(Guid pluginClsid)
	{
		_syncGate.Wait();
		Mutex? crossProcess = AcquireCrossProcessLock();
		if (crossProcess == null)
		{
			_syncGate.Release();
			Log.Warn("could not acquire cross-process cache lock, skipping clear");
			return false;
		}
		try
		{
			int hrGet = ReadCache(pluginClsid, out var entries);
			if (hrGet < HResults.S_OK) Log.Error($"GetAllCredentials hr=0x{hrGet:X8}");

			int listed = entries.Count;
			if (listed > 0) ApplyRemove(pluginClsid, entries);

			// Verify: a per-credential remove only reaches rows GetAllCredentials can address.
			ReadCache(pluginClsid, out var remaining);
			if (remaining.Count == 0)
			{
				Log.Info($"cleared={listed}");
				return true;
			}

			// Fallback only: RemoveAllCredentials did not work in the original native implementation.
			int hr = WebAuthnPluginApi.WebAuthNPluginAuthenticatorRemoveAllCredentials(pluginClsid);
			Log.Warn($"{remaining.Count} credential(s) left after per-credential remove, RemoveAllCredentials hr=0x{hr:X8}");

			ReadCache(pluginClsid, out var afterFallback);
			if (afterFallback.Count > 0)
			{
				Log.Error($"cache still holds {afterFallback.Count} credential(s) after RemoveAllCredentials");
				return false;
			}

			Log.Info($"cleared={listed}");
			return true;
		}
		catch (Exception ex)
		{
			Log.Error($"exception {ex.GetType().Name}: {ex.Message}");
			return false;
		}
		finally
		{
			ReleaseCrossProcessLock(crossProcess);
			_syncGate.Release();
		}
	}

	/// <summary>Writes both sides of the sync comparison; read-only. Backs /dumpcredentials.</summary>
	public static void DumpCredentials(Guid pluginClsid, Action<string> write)
	{
		var pipeClient = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)));
		var response = pipeClient.GetCredentials(new GetCredentialsRequest());
		if (response == null)
			write("KeePass unavailable (is it running with a database open?)");
		else if (response.ErrorCode != null)
			write($"KeePass returned error={response.ErrorCode} {response.ErrorMessage}");

		var kpCredentials = response?.ErrorCode == null
			? ParseKeePassCredentials(response?.Credentials)
			: [];

		uint cExisting = 0;
		WebAuthnPluginCredentialDetails* pExisting = null;
		int hrGet = WebAuthnPluginApi.WebAuthNPluginAuthenticatorGetAllCredentials(
			pluginClsid, &cExisting, &pExisting);
		if (hrGet < HResults.S_OK)
		{
			write($"GetAllCredentials failed hr=0x{hrGet:X8}");
			return;
		}

		var existingList = new List<ManagedCredentialDetails>();
		if (pExisting != null)
		{
			for (uint i = 0; i < cExisting; i++)
				existingList.Add(ManagedCredentialDetails.FromNative(&pExisting[i]));
			WebAuthnPluginApi.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(cExisting, pExisting);
		}

		write($"Windows cache ({existingList.Count}):");
		foreach (var c in existingList) write("  " + Describe(c));
		write($"KeePass ({kpCredentials.Count}):");
		foreach (var c in kpCredentials) write("  " + Describe(c));

		int matched = kpCredentials.Count(kp => existingList.Any(ex => SameCredential(ex, kp)));
		int identical = kpCredentials.Count(kp =>
			existingList.Any(ex => SameCredential(ex, kp) && SamePayload(ex, kp)));
		write($"cached: {matched} of {kpCredentials.Count}, of which unchanged: {identical}");
	}

	private static bool SyncToCredentialCache(Guid pluginClsid)
	{
		// 1. Query credentials from KeePass
		var pipeClient = new PipeClient(msg => Log.Debug(msg, nameof(PipeClient)));
		var response = pipeClient.GetCredentials(new GetCredentialsRequest());
		if (response == null)
		{
			Log.Info("KeePass unavailable or error, skipping credential sync");
			return false;
		}
		if (response.ErrorCode != null)
		{
			Log.Warn($"GetCredentials returned error={response.ErrorCode} errorMessage={response.ErrorMessage}, skipping credential sync");
			return false;
		}

		// 2. Parse credential list
		var kpCredentials = ParseKeePassCredentials(response.Credentials);

		// 3. Get Windows cache
		uint cExisting = 0;
		WebAuthnPluginCredentialDetails* pExisting = null;
		int hrGet = WebAuthnPluginApi.WebAuthNPluginAuthenticatorGetAllCredentials(
			pluginClsid, &cExisting, &pExisting);
		if (hrGet < HResults.S_OK) Log.Error($"GetAllCredentials hr=0x{hrGet:X8}");

		// Collect existing entries as managed objects for comparison
		var existingList = new List<ManagedCredentialDetails>();
		if (hrGet >= HResults.S_OK && cExisting > 0 && pExisting != null)
		{
			for (uint i = 0; i < cExisting; i++)
				existingList.Add(ManagedCredentialDetails.FromNative(&pExisting[i]));
		}

		// 4. Diff. Identity is credentialId + rpId (what Windows keys on), the display fields are
		// payload. Each credential claims one row, so a leftover duplicate row ends up in toRemove.
		var toRemove = new List<ManagedCredentialDetails>();
		var toAdd = new List<ManagedCredentialDetails>();
		var unclaimed = new List<ManagedCredentialDetails>(existingList);
		int unchanged = 0;

		foreach (var kp in kpCredentials)
		{
			// Prefer an already-correct row, so shedding a duplicate does not rewrite the good one.
			int idx = unclaimed.FindIndex(ex => SameCredential(ex, kp) && SamePayload(ex, kp));
			if (idx < 0) idx = unclaimed.FindIndex(ex => SameCredential(ex, kp));
			if (idx < 0)
			{
				toAdd.Add(kp);
				continue;
			}

			var claimed = unclaimed[idx];
			unclaimed.RemoveAt(idx);
			if (SamePayload(claimed, kp))
			{
				unchanged++;
			}
			else
			{
				toRemove.Add(claimed);
				toAdd.Add(kp);
			}
		}

		toRemove.AddRange(unclaimed);

		// 5. Apply - remove first (pExisting pointers still valid), then free, then add
		if (toRemove.Count > 0)
		{
			ApplyRemove(pluginClsid, toRemove);
		}

		if (pExisting != null)
			WebAuthnPluginApi.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(cExisting, pExisting);

		if (toAdd.Count > 0)
		{
			ApplyAdd(pluginClsid, toAdd);
		}

		Log.Info($"sync done removed={toRemove.Count} added={toAdd.Count} unchanged={unchanged}");
		return true;
	}

	private static void ApplyRemove(Guid pluginClsid, List<ManagedCredentialDetails> items)
	{
		foreach (var item in items)
		{
			int hr = ApplyOne(pluginClsid, item, remove: true);
			// Already gone, which is the state we wanted.
			if (hr == HResults.NTE_NOT_FOUND) continue;
			if (hr < HResults.S_OK)
				Log.Error($"RemoveCredential hr=0x{hr:X8} {Describe(item)}", nameof(SyncToCredentialCache));
		}
	}

	private static void ApplyAdd(Guid pluginClsid, List<ManagedCredentialDetails> items)
	{
		foreach (var item in items)
		{
			int hr = ApplyOne(pluginClsid, item, remove: false);
			// Already cached, which is the state we wanted.
			if (hr == HResults.NTE_EXISTS) continue;
			if (hr < HResults.S_OK)
				Log.Error($"AddCredential hr=0x{hr:X8} {Describe(item)}", nameof(SyncToCredentialCache));
		}
	}

	// One per call: these APIs take an array but return a single HRESULT, so one rejected row
	// discards the whole batch.
	private static int ApplyOne(Guid pluginClsid, ManagedCredentialDetails item, bool remove)
	{
		var pinned = new List<GCHandle>();
		try
		{
			var natives = BuildNativeArray([item], pinned);
			fixed (WebAuthnPluginCredentialDetails* ptr = natives)
			{
				return remove
					? WebAuthnPluginApi.WebAuthNPluginAuthenticatorRemoveCredentials(pluginClsid, 1, ptr)
					: WebAuthnPluginApi.WebAuthNPluginAuthenticatorAddCredentials(pluginClsid, 1, ptr);
			}
		}
		finally
		{
			foreach (var h in pinned) h.Free();
		}
	}

	private static unsafe WebAuthnPluginCredentialDetails[] BuildNativeArray(
		List<ManagedCredentialDetails> items, List<GCHandle> pinned)
	{
		var arr = new WebAuthnPluginCredentialDetails[items.Count];
		for (int i = 0; i < items.Count; i++)
		{
			var item = items[i];
			var hCredId = GCHandle.Alloc(item.CredentialId, GCHandleType.Pinned);
			var hUserId = GCHandle.Alloc(item.UserId.Length > 0 ? item.UserId : new byte[1], GCHandleType.Pinned);
			var hRpId = GCHandle.Alloc(item.RpId, GCHandleType.Pinned);
			var hRpName = GCHandle.Alloc(item.RpName, GCHandleType.Pinned);
			var hUserName = GCHandle.Alloc(item.UserName, GCHandleType.Pinned);
			var hDispName = GCHandle.Alloc(item.UserDisplayName, GCHandleType.Pinned);
			pinned.AddRange([hCredId, hUserId, hRpId, hRpName, hUserName, hDispName]);

			arr[i].cbCredentialId = (uint)item.CredentialId.Length;
			arr[i].pbCredentialId = item.CredentialId.Length > 0
				? (byte*)hCredId.AddrOfPinnedObject()
				: null;
			arr[i].pwszRpId = (char*)hRpId.AddrOfPinnedObject();
			arr[i].pwszRpName = (char*)hRpName.AddrOfPinnedObject();
			arr[i].cbUserId = (uint)item.UserId.Length;
			arr[i].pbUserId = item.UserId.Length > 0
				? (byte*)hUserId.AddrOfPinnedObject()
				: null;
			arr[i].pwszUserName = (char*)hUserName.AddrOfPinnedObject();
			arr[i].pwszUserDisplayName = (char*)hDispName.AddrOfPinnedObject();
		}
		return arr;
	}

	private static List<ManagedCredentialDetails> ParseKeePassCredentials(List<CredentialInfo>? credentials)
	{
		if (credentials == null) return [];

		var result = new List<ManagedCredentialDetails>(credentials.Count);
		var seen = new HashSet<string>(StringComparer.Ordinal);
		foreach (var c in credentials)
		{
			if (string.IsNullOrEmpty(c.CredentialId) || string.IsNullOrEmpty(c.RpId))
				continue;

			// Windows keys the cache on the credential id, so one passkey held by several entries
			// is still one row; offering it twice is rejected with NTE_EXISTS.
			if (!seen.Add(c.CredentialId))
			{
				Log.Debug($"skipping duplicate credential id for rpId={c.RpId}");
				continue;
			}

			byte[] credId = Base64Url.Decode(c.CredentialId);
			byte[] userId = string.IsNullOrEmpty(c.UserHandle) ? [] : Base64Url.Decode(c.UserHandle);
			string rpId = c.RpId;
			string rpName = c.RpId; // use rpId as rpName
			string userName = c.UserName ?? string.Empty;
			string dispName = !string.IsNullOrEmpty(c.Title) ? c.Title : c.RpId;

			result.Add(new ManagedCredentialDetails(credId, rpId, rpName, userId, userName, dispName));
		}
		return result;
	}

	/// <summary>Reads the cache and frees the native array. Returns the underlying HRESULT.</summary>
	private static int ReadCache(Guid pluginClsid, out List<ManagedCredentialDetails> entries)
	{
		entries = [];

		uint cExisting = 0;
		WebAuthnPluginCredentialDetails* pExisting = null;
		int hr = WebAuthnPluginApi.WebAuthNPluginAuthenticatorGetAllCredentials(
			pluginClsid, &cExisting, &pExisting);
		if (pExisting == null) return hr;

		if (hr >= HResults.S_OK)
		{
			for (uint i = 0; i < cExisting; i++)
				entries.Add(ManagedCredentialDetails.FromNative(&pExisting[i]));
		}

		WebAuthnPluginApi.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(cExisting, pExisting);
		return hr;
	}

	/// <summary>Same credential as far as Windows is concerned. Display fields are not identity.</summary>
	private static bool SameCredential(ManagedCredentialDetails a, ManagedCredentialDetails b) =>
		a.CredentialId.AsSpan().SequenceEqual(b.CredentialId)
		&& string.Equals(a.RpId, b.RpId, StringComparison.OrdinalIgnoreCase);

	/// <summary>What the sign-in UI displays. A difference here is an update, not a new credential.</summary>
	private static bool SamePayload(ManagedCredentialDetails a, ManagedCredentialDetails b) =>
		a.UserName == b.UserName
		&& a.UserDisplayName == b.UserDisplayName
		&& a.UserId.AsSpan().SequenceEqual(b.UserId);

	private static string Describe(ManagedCredentialDetails c) =>
		$"credId={ShortId(c.CredentialId)} rpId={c.RpId} rpName={c.RpName} " +
		$"userName={Pii(c.UserName)} displayName={Pii(c.UserDisplayName)} userId={ShortId(c.UserId)}";

	// Length plus a prefix is enough to line two entries up.
	private static string ShortId(byte[] bytes) => bytes.Length == 0
		? "<empty>"
		: $"[{bytes.Length}]{Convert.ToHexString(bytes, 0, Math.Min(4, bytes.Length))}";

	// Debug: the value. Release: length plus a short hash, so shared logs carry no usernames but
	// stay comparable.
	private static string Pii(string value)
	{
		if (value.Length == 0) return "<empty>";
#if DEBUG
		return value;
#else
		byte[] hash = System.Security.Cryptography.SHA256.HashData(
			System.Text.Encoding.UTF8.GetBytes(value));
		return $"<len={value.Length},h={Convert.ToHexString(hash, 0, 2)}>";
#endif
	}

	// Managed mirror of WebAuthnPluginCredentialDetails for diffing
	private sealed record ManagedCredentialDetails(
		byte[] CredentialId,
		string RpId,
		string RpName,
		byte[] UserId,
		string UserName,
		string UserDisplayName)
	{
		public static ManagedCredentialDetails FromNative(WebAuthnPluginCredentialDetails* p)
		{
			byte[] credId = p->cbCredentialId > 0
				? new ReadOnlySpan<byte>(p->pbCredentialId, (int)p->cbCredentialId).ToArray()
				: [];
			byte[] userId = p->cbUserId > 0
				? new ReadOnlySpan<byte>(p->pbUserId, (int)p->cbUserId).ToArray()
				: [];
			return new ManagedCredentialDetails(
				credId,
				p->pwszRpId != null ? new string(p->pwszRpId) : string.Empty,
				p->pwszRpName != null ? new string(p->pwszRpName) : string.Empty,
				userId,
				p->pwszUserName != null ? new string(p->pwszUserName) : string.Empty,
				p->pwszUserDisplayName != null ? new string(p->pwszUserDisplayName) : string.Empty);
		}

	}
}
