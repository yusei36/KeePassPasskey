using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskeyPlugin.Ipc
{
    /// <summary>
    /// Verifies that connecting pipe clients are legitimate KeePassPasskeyProvider instances.
    /// Supports both MSIX-packaged apps and standalone signed executables.
    /// </summary>
    internal static class ClientVerifier
    {
        // Expected package family name for the MSIX-packaged provider
        private const string ExpectedPackageFamilyName = "KeePassPasskeyProvider";

        // Expected executable name
        private const string ExpectedExeName = "KeePassPasskeyProvider.exe";

        /// <summary>
        /// Verifies that the client connected to the pipe is the legitimate provider.
        /// </summary>
        /// <param name="pipeHandle">The native handle of the connected pipe.</param>
        /// <param name="reason">If verification fails, contains the reason.</param>
        /// <returns>True if the client is verified, false otherwise.</returns>
        public static bool VerifyClient(SafePipeHandle pipeHandle, out string reason)
        {
            reason = null;

            try
            {
                // 1. Get the client process ID
                if (!GetNamedPipeClientProcessId(pipeHandle, out uint clientPid))
                {
                    reason = "Failed to get client process ID";
                    return false;
                }

                // 2. Get process information
                Process clientProcess;
                try
                {
                    clientProcess = Process.GetProcessById((int)clientPid);
                }
                catch (ArgumentException)
                {
                    reason = $"Client process {clientPid} no longer exists";
                    return false;
                }

                // 3. Get the executable path
                string exePath;
                try
                {
                    exePath = GetProcessPath(clientPid);
                }
                catch (Exception ex)
                {
                    reason = $"Failed to get process path: {ex.Message}";
                    return false;
                }

                if (string.IsNullOrEmpty(exePath))
                {
                    reason = "Could not determine client executable path";
                    return false;
                }

                // 4. Check if it's an MSIX package
                string packageFamilyName = GetPackageFamilyName(clientPid);
                if (!string.IsNullOrEmpty(packageFamilyName))
                {
                    return VerifyMsixPackage(packageFamilyName, exePath, out reason);
                }

                // 5. If not packaged, verify Authenticode signature
                return VerifySignature(exePath, out reason);
            }
            catch (Exception ex)
            {
                reason = $"Verification error: {ex.Message}";
                return false;
            }
        }

        private static bool VerifyMsixPackage(string packageFamilyName, string exePath, out string reason)
        {
            reason = null;

            // Check package family name contains expected identifier
            if (!packageFamilyName.StartsWith(ExpectedPackageFamilyName, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Unexpected package: {packageFamilyName}";
                return false;
            }

            // Verify path is in WindowsApps (protected directory)
            string windowsApps = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "WindowsApps");

            if (!exePath.StartsWith(windowsApps, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Package not in WindowsApps: {exePath}";
                return false;
            }

            // Verified: it's our MSIX package running from protected location
            return true;
        }

        private static bool VerifySignature(string exePath, out string reason)
        {
            reason = null;

            // Check executable name
            string fileName = Path.GetFileName(exePath);
            if (!fileName.Equals(ExpectedExeName, StringComparison.OrdinalIgnoreCase))
            {
                reason = $"Unexpected executable: {fileName}";
                return false;
            }

            // Verify Authenticode signature
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(exePath);
                if (cert == null)
                {
                    reason = "Executable is not signed";
                    return false;
                }

                // Optionally verify specific certificate properties
                // For now, just verify it's signed
                var cert2 = new X509Certificate2(cert);

                // Check certificate is valid
                if (cert2.NotAfter < DateTime.Now || cert2.NotBefore > DateTime.Now)
                {
                    reason = "Signing certificate has expired or is not yet valid";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                reason = $"Signature verification failed: {ex.Message}";
                return false;
            }
        }

        private static string GetProcessPath(uint pid)
        {
            // Use QueryFullProcessImageName for better compatibility
            IntPtr hProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var buffer = new char[4096];
                uint size = (uint)buffer.Length;

                if (!QueryFullProcessImageName(hProcess, 0, buffer, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return new string(buffer, 0, (int)size);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private static string GetPackageFamilyName(uint pid)
        {
            IntPtr hProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid);

            if (hProcess == IntPtr.Zero)
                return null;

            try
            {
                uint length = 0;
                int result = GetPackageFamilyName(hProcess, ref length, null);

                // APPMODEL_ERROR_NO_PACKAGE means process is not packaged
                if (result == APPMODEL_ERROR_NO_PACKAGE)
                    return null;

                if (result != ERROR_INSUFFICIENT_BUFFER || length == 0)
                    return null;

                var buffer = new char[length];
                result = GetPackageFamilyName(hProcess, ref length, buffer);

                if (result != ERROR_SUCCESS)
                    return null;

                // length includes null terminator
                return new string(buffer, 0, (int)length - 1);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        #region Native Methods

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int APPMODEL_ERROR_NO_PACKAGE = 15700;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(
            SafePipeHandle Pipe,
            out uint ClientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(
            IntPtr hProcess,
            uint dwFlags,
            [Out] char[] lpExeName,
            ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetPackageFamilyName(
            IntPtr hProcess,
            ref uint packageFamilyNameLength,
            [Out] char[] packageFamilyName);

        #endregion
    }
}
