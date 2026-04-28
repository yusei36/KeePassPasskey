using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskey.Ipc
{
    /// <summary>
    /// Verifies that connecting pipe clients are legitimate KeePassPasskeyProvider instances.
    /// </summary>
    internal static class ClientVerifier
    {
        // Expected package family name for the MSIX-packaged provider.
        // Debug builds accept any package starting with the base name to allow self-signed dev certs.
#if DEBUG
        private const string ExpectedPackageFamilyName = "KeePassPasskeyProvider";
#else
        private const string ExpectedPackageFamilyName = "KeePassPasskeyProvider_rcm79ea08mqe4";
#endif

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

                // 2. Verify the client is our MSIX-packaged provider.
                // The Package Family Name is derived from the package name and a hash of the
                // publisher certificate's public key. Only packages signed with a matching
                // private key can produce this exact PFN.
                string packageFamilyName = GetPackageFamilyName(clientPid);
                if (packageFamilyName == null)
                {
                    reason = "Client is not an MSIX-packaged application";
                    return false;
                }

#if DEBUG
                if (!packageFamilyName.StartsWith(ExpectedPackageFamilyName, StringComparison.OrdinalIgnoreCase))
#else
                if (!packageFamilyName.Equals(ExpectedPackageFamilyName, StringComparison.OrdinalIgnoreCase))
#endif
                {
                    reason = $"Unexpected package: {packageFamilyName}";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                reason = $"Verification error: {ex.Message}";
                return false;
            }
        }

        private static string GetPackageFamilyName(uint pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
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
        private static extern bool GetNamedPipeClientProcessId(SafePipeHandle Pipe, out uint ClientProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetPackageFamilyName(IntPtr hProcess, ref uint packageFamilyNameLength, [Out] char[] packageFamilyName);

        #endregion
    }
}
