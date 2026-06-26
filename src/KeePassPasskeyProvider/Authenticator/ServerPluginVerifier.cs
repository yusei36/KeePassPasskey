// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
#if !DEBUG
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KeePassPasskeyShared;
using KeePassPasskeyShared.Ipc;

namespace KeePassPasskeyProvider.Authenticator;

// Null-returning string helpers mean "no value"; the obsolete Authenticode cert APIs have no replacement.
#nullable disable
#pragma warning disable SYSLIB0057

/// <summary>
/// Release-only check that the KeePass process serving the pipe has our plugin DLL loaded, signed by
/// the same cert as this provider's MSIX. Registered via a module initializer so it is active before
/// any <see cref="PipeClient"/> call; compiled out in Debug, where local plugin builds are unsigned.
/// </summary>
internal static class ServerPluginVerifier
{
    private const string PluginDllName = "KeePassPasskey.dll";

    [ModuleInitializer]
    internal static void Register()
    {
        ServerVerifier.PluginSignatureValidator = ValidatePluginSignature;
    }

    /// <summary>Returns null if the server's loaded plugin DLL is validly signed by our cert; otherwise a reason.</summary>
    private static string ValidatePluginSignature(uint serverPid)
    {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, serverPid);
        if (hProcess == IntPtr.Zero)
        {
            // Cannot inspect the server (e.g. KeePass elevated). Not a bypass: a same-user squatter is
            // at equal integrity and inspectable; only a higher-integrity target, which outranks this, fails.
            Log.Warn($"cannot open server process {serverPid} (err {Marshal.GetLastWin32Error()}); skipping plugin signature pin");
            return null;
        }

        try
        {
            string dllPath = FindLoadedModule(hProcess, PluginDllName);
            if (dllPath == null)
                return $"Plugin DLL '{PluginDllName}' is not loaded in the server process";

            if (!IsAuthenticodeSignatureValid(dllPath))
                return "Plugin DLL Authenticode signature is missing or invalid";

            string dllThumbprint;
            using (var dllCert = new X509Certificate2(X509Certificate.CreateFromSignedFile(dllPath)))
                dllThumbprint = dllCert.Thumbprint;

            string expectedThumbprint = GetOwnPackageSignerThumbprint();
            if (expectedThumbprint == null)
                return "could not determine own package signer to verify the plugin DLL";

            if (!string.Equals(dllThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                return $"Plugin DLL is signed by an unexpected certificate ({dllThumbprint})";

            return null;
        }
        catch (Exception ex)
        {
            Log.Warn($"plugin signature validation failed: {ex.Message}");
            return $"plugin signature validation error: {ex.Message}";
        }
        finally
        {
            CloseHandle(hProcess);
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

    private static string FindLoadedModule(IntPtr hProcess, string moduleName)
    {
        IntPtr[] modules = new IntPtr[1024];
        int byteSize = modules.Length * IntPtr.Size;
        if (!EnumProcessModulesEx(hProcess, modules, byteSize, out int needed, LIST_MODULES_ALL))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        int count = Math.Min(needed / IntPtr.Size, modules.Length);
        var sb = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            sb.Clear();
            if (GetModuleFileNameEx(hProcess, modules[i], sb, sb.Capacity) == 0)
                continue;
            string path = sb.ToString();
            if (string.Equals(Path.GetFileName(path), moduleName, StringComparison.OrdinalIgnoreCase))
                return path;
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

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint LIST_MODULES_ALL = 0x03;

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    #endregion
}
#endif
