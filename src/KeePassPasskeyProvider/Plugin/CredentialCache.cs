using System.Runtime.InteropServices;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Ipc;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Plugin;

/// <summary>
/// Synchronises KeePass credentials with the Windows platform autofill cache.
/// Mirrors CredentialCache.cpp — diff-based add/remove to minimise API calls.
/// </summary>
internal static unsafe class CredentialCache
{
    /// <summary>
    /// Query KeePass for all passkeys and push changes to the Windows cache.
    /// Returns immediately (not an error) if KeePass is unavailable.
    /// </summary>
    public static void SyncToWindowsCache(Guid pluginClsid)
    {
        try
        {
            SyncToWindowsCacheCore(pluginClsid);
        }
        catch (Exception ex)
        {
            Log.Write($"CredentialCache.SyncToWindowsCache: exception {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static void SyncToWindowsCacheCore(Guid pluginClsid)
    {
        // 1. Query credentials from KeePass
        var req = new IpcRequest { Type = "get_credentials", RequestId = "sync" };
        if (!PipeClient.SendRequest(req, out var resp) || resp == null || resp.Type == "error")
        {
            Log.Write("CredentialCache: KeePass unavailable or error, skipping sync");
            return;
        }

        // 2. Parse credential list
        var kpCredentials = ParseKeePassCredentials(resp.Credentials);
        Log.Write($"CredentialCache: KeePass returned {kpCredentials.Count} credentials");

        // 3. Get Windows cache
        uint cExisting = 0;
        WebAuthnPluginCredentialDetails* pExisting = null;
        int hrGet = WebAuthnPluginApi.WebAuthNPluginAuthenticatorGetAllCredentials(
            pluginClsid, &cExisting, &pExisting);
        Log.Write($"CredentialCache: GetAllCredentials hr=0x{hrGet:X8} count={cExisting}");

        // Collect existing entries as managed objects for comparison
        var existingList = new List<ManagedCredentialDetails>();
        if (hrGet >= 0 && cExisting > 0 && pExisting != null)
        {
            for (uint i = 0; i < cExisting; i++)
                existingList.Add(ManagedCredentialDetails.FromNative(&pExisting[i]));
        }

        // 4. Diff
        var toRemove = new List<ManagedCredentialDetails>();
        foreach (var ex in existingList)
        {
            bool matchedAndSame = kpCredentials.Any(kp => kp.Equals(ex));
            if (!matchedAndSame) toRemove.Add(ex);
        }

        var toAdd = new List<ManagedCredentialDetails>();
        foreach (var kp in kpCredentials)
        {
            bool matchedAndSame = existingList.Any(ex => ex.Equals(kp));
            if (!matchedAndSame) toAdd.Add(kp);
        }

        // 5. Apply — remove first (pExisting pointers still valid), then free, then add
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

        Log.Write($"CredentialCache: sync done removed={toRemove.Count} added={toAdd.Count} unchanged={kpCredentials.Count - toAdd.Count}");
    }

    private static void ApplyRemove(Guid pluginClsid, List<ManagedCredentialDetails> items)
    {
        // Pin all byte arrays, build native struct array, call RemoveCredentials
        var pinned = new List<GCHandle>();
        try
        {
            var natives = BuildNativeArray(items, pinned);
            fixed (WebAuthnPluginCredentialDetails* ptr = natives)
            {
                int hr = WebAuthnPluginApi.WebAuthNPluginAuthenticatorRemoveCredentials(
                    pluginClsid, (uint)natives.Length, ptr);
                Log.Write($"CredentialCache: RemoveCredentials hr=0x{hr:X8} count={natives.Length}");
            }
        }
        finally
        {
            foreach (var h in pinned) h.Free();
        }
    }

    private static void ApplyAdd(Guid pluginClsid, List<ManagedCredentialDetails> items)
    {
        var pinned = new List<GCHandle>();
        try
        {
            var natives = BuildNativeArray(items, pinned);
            fixed (WebAuthnPluginCredentialDetails* ptr = natives)
            {
                int hr = WebAuthnPluginApi.WebAuthNPluginAuthenticatorAddCredentials(
                    pluginClsid, (uint)natives.Length, ptr);
                Log.Write($"CredentialCache: AddCredentials hr=0x{hr:X8} count={natives.Length}");
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
            var hCredId   = GCHandle.Alloc(item.CredentialId, GCHandleType.Pinned);
            var hUserId   = GCHandle.Alloc(item.UserId.Length > 0 ? item.UserId : new byte[1], GCHandleType.Pinned);
            var hRpId     = GCHandle.Alloc(item.RpId,             GCHandleType.Pinned);
            var hRpName   = GCHandle.Alloc(item.RpName,           GCHandleType.Pinned);
            var hUserName = GCHandle.Alloc(item.UserName,         GCHandleType.Pinned);
            var hDispName = GCHandle.Alloc(item.UserDisplayName,  GCHandleType.Pinned);
            pinned.AddRange([hCredId, hUserId, hRpId, hRpName, hUserName, hDispName]);

            arr[i].cbCredentialId = (uint)item.CredentialId.Length;
            arr[i].pbCredentialId = item.CredentialId.Length > 0
                ? (byte*)hCredId.AddrOfPinnedObject()
                : null;
            arr[i].pwszRpId            = (char*)hRpId.AddrOfPinnedObject();
            arr[i].pwszRpName          = (char*)hRpName.AddrOfPinnedObject();
            arr[i].cbUserId            = (uint)item.UserId.Length;
            arr[i].pbUserId            = item.UserId.Length > 0
                ? (byte*)hUserId.AddrOfPinnedObject()
                : null;
            arr[i].pwszUserName        = (char*)hUserName.AddrOfPinnedObject();
            arr[i].pwszUserDisplayName = (char*)hDispName.AddrOfPinnedObject();
        }
        return arr;
    }

    private static List<ManagedCredentialDetails> ParseKeePassCredentials(List<CredentialInfo>? credentials)
    {
        if (credentials == null) return [];

        var result = new List<ManagedCredentialDetails>(credentials.Count);
        foreach (var c in credentials)
        {
            if (string.IsNullOrEmpty(c.CredentialId) || string.IsNullOrEmpty(c.RpId))
                continue;

            byte[] credId   = Base64Url.Decode(c.CredentialId);
            byte[] userId   = string.IsNullOrEmpty(c.UserHandle) ? [] : Base64Url.Decode(c.UserHandle);
            string rpId     = c.RpId;
            string rpName   = c.RpId; // use rpId as rpName (matches C++ code)
            string userName = c.UserName ?? string.Empty;
            string dispName = !string.IsNullOrEmpty(c.Title) ? c.Title : c.RpId;

            result.Add(new ManagedCredentialDetails(credId, rpId, rpName, userId, userName, dispName));
        }
        return result;
    }

    // Managed mirror of WebAuthnPluginCredentialDetails for diffing
    private record ManagedCredentialDetails(
        byte[]  CredentialId,
        string  RpId,
        string  RpName,
        byte[]  UserId,
        string  UserName,
        string  UserDisplayName)
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
                p->pwszRpId   != null ? new string(p->pwszRpId)   : string.Empty,
                p->pwszRpName != null ? new string(p->pwszRpName) : string.Empty,
                userId,
                p->pwszUserName        != null ? new string(p->pwszUserName)        : string.Empty,
                p->pwszUserDisplayName != null ? new string(p->pwszUserDisplayName) : string.Empty);
        }

        // Equality mirrors the C++ credEq lambda
        public virtual bool Equals(ManagedCredentialDetails? other)
        {
            if (other is null) return false;
            return CredentialId.AsSpan().SequenceEqual(other.CredentialId)
                && RpId == other.RpId
                && UserName == other.UserName
                && UserDisplayName == other.UserDisplayName
                && UserId.AsSpan().SequenceEqual(other.UserId);
        }

        public override int GetHashCode() => CredentialId.Length; // imprecise but acceptable
    }
}
