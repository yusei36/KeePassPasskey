// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
#if !DEBUG
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Authenticator;

// Null-returning string helpers mean "no value"; the obsolete Authenticode cert APIs have no replacement.
#nullable disable
#pragma warning disable SYSLIB0057

/// <summary>
/// Release-only check (compiled out in Debug) that the KeePass process serving the pipe carries our
/// signed plugin DLL. KeePass loads plugins as managed assemblies invisible to module enumeration, so
/// we verify the on-disk file in its plugin directories. Registered via a module initializer.
/// </summary>
internal static class ServerPluginVerifier
{
    private const string PluginDllName = "KeePassPasskey.dll";

    [ModuleInitializer]
    internal static void Register()
    {
        ServerVerifier.PluginSignatureValidator = ValidatePluginSignature;
    }

    /// <summary>
    /// Returns a reason only when the copy KeePass actually loaded (the locked one) is foreign-signed;
    /// fail-open in every other case. The lock binds the verdict to the loaded copy among duplicates.
    /// </summary>
    private static string ValidatePluginSignature(uint serverPid, string serverImagePath)
    {
        try
        {
            if (string.IsNullOrEmpty(serverImagePath))
            {
                Log.Warn("server image path unavailable; skipping plugin signature pin");
                return null;
            }

            string appDir = Path.GetDirectoryName(serverImagePath);
            if (string.IsNullOrEmpty(appDir))
            {
                Log.Warn($"could not derive KeePass directory from '{serverImagePath}'; skipping plugin signature pin");
                return null;
            }

            string expectedThumbprint = GetOwnPackageSignerThumbprint();
            if (expectedThumbprint == null)
            {
                Log.Warn("could not determine own package signer; skipping plugin signature pin");
                return null;
            }

            bool ourCopyPresent = false;
            bool foreignLoaded = false;
            bool foreignPresent = false;
            foreach (string candidate in EnumeratePluginCandidates(appDir))
            {
                if (!IsAuthenticodeSignatureValid(candidate))
                    continue;

                string thumbprint;
                using (var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(candidate)))
                    thumbprint = cert.Thumbprint;

                bool ours = string.Equals(thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);
                bool loaded = IsFileHeldOpen(candidate);

                if (ours)
                {
                    if (loaded)
                        return null;
                    ourCopyPresent = true;
                }
                else
                {
                    foreignPresent = true;
                    if (loaded)
                        foreignLoaded = true;
                }
            }

            if (foreignLoaded)
                return $"The loaded '{PluginDllName}' is signed by an unexpected certificate";

            if (ourCopyPresent)
                return null;

            if (foreignPresent)
                Log.Warn($"only a foreign-signed, non-loaded '{PluginDllName}' was found under '{appDir}'; skipping plugin signature pin");
            else
                Log.Warn($"no validly signed '{PluginDllName}' found under '{appDir}'; skipping plugin signature pin");
            return null;
        }
        catch (Exception ex)
        {
            Log.Warn($"plugin signature validation failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// True if another process holds the file open (KeePass locks a loaded plugin for its lifetime).
    /// Read-only no-share probe so it works in Program Files; false when undeterminable.
    /// </summary>
    private static bool IsFileHeldOpen(string path)
    {
        try
        {
            using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
                return false;
        }
        // ERROR_SHARING_VIOLATION (0x20) / ERROR_LOCK_VIOLATION (0x21): held open elsewhere.
        catch (IOException ex) when ((ex.HResult & 0xFFFF) == 0x20 || (ex.HResult & 0xFFFF) == 0x21)
        {
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn($"could not determine lock state of '{path}': {ex.Message}");
            return false;
        }
    }

    /// <summary>AppDir (top level) and AppDir\Plugins (recursive), where KeePass loads plugins from.</summary>
    private static IEnumerable<string> EnumeratePluginCandidates(string appDir)
    {
        foreach (string f in SafeEnumerateFiles(appDir, recurse: false))
            yield return f;

        string pluginsDir = Path.Combine(appDir, "Plugins");
        foreach (string f in SafeEnumerateFiles(pluginsDir, recurse: true))
            yield return f;
    }

    private static IEnumerable<string> SafeEnumerateFiles(string dir, bool recurse)
    {
        if (!Directory.Exists(dir))
            return Array.Empty<string>();
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = recurse,
                IgnoreInaccessible = true,
                MaxRecursionDepth = 16,
            };
            return Directory.EnumerateFiles(dir, PluginDllName, options);
        }
        catch (Exception ex)
        {
            Log.Warn($"could not enumerate '{dir}': {ex.Message}");
            return Array.Empty<string>();
        }
    }

    /// <summary>Thumbprint of the certificate that signed this provider's MSIX package, or null.</summary>
    private static string GetOwnPackageSignerThumbprint()
    {
        string p7xPath = FindAppxSignature();
        if (p7xPath == null)
            return null;

        byte[] raw = File.ReadAllBytes(p7xPath);
        // AppxSignature.p7x is a DER PKCS#7 prefixed with the 4-byte magic "PKCX".
        int offset = raw.Length >= 4 && raw[0] == (byte)'P' && raw[1] == (byte)'K'
                     && raw[2] == (byte)'C' && raw[3] == (byte)'X' ? 4 : 0;
        byte[] pkcs7 = offset == 0 ? raw : raw.AsSpan(offset).ToArray();

        var certs = new X509Certificate2Collection();
        certs.Import(pkcs7);
        if (certs.Count == 0)
            return null;

        // The leaf is the cert that is not the issuer of any other in the set (the only cert when self-signed).
        var all = certs.Cast<X509Certificate2>().ToList();
        X509Certificate2 leaf = all.FirstOrDefault(c => !all.Any(o => !ReferenceEquals(o, c) && o.Issuer == c.Subject)) ?? all[0];
        return leaf.Thumbprint;
    }

    private static string FindAppxSignature()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "AppxSignature.p7x");
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

    private static bool IsAuthenticodeSignatureValid(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath),
        };
        IntPtr pFileInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());

        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = pFileInfo,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE,
        };
        IntPtr pData = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_DATA>());

        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            Marshal.StructureToPtr(data, pData, false);

            int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            // Accept an untrusted (self-signed) root since the signer thumbprint is pinned separately.
            return result == 0 || (uint)result == CERT_E_UNTRUSTEDROOT;
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            Marshal.FreeCoTaskMem(pFileInfo);
            Marshal.FreeCoTaskMem(pData);
        }
    }

    #region Native methods

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    #endregion
}
#endif
