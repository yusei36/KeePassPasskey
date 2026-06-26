// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskeyShared.Ipc
{
    /// <summary>
    /// Verifies the pipe server a client connected to is the KeePass process hosting the plugin, not
    /// a squatter. Best-effort; paired with FILE_FLAG_FIRST_PIPE_INSTANCE detection on the server.
    /// </summary>
    public static class ServerVerifier
    {
        private const string ExpectedServerImage = "KeePass.exe";

        /// <summary>
        /// Optional extra server check (the provider registers it, Release only): given the server
        /// process id, returns null on success or a failure reason. Null delegate skips the check.
        /// </summary>
        public static Func<uint, string> PluginSignatureValidator;

        /// <summary>
        /// Verifies the server end of a connected client pipe.
        /// </summary>
        /// <param name="pipeHandle">The native handle of the connected client pipe.</param>
        /// <param name="reason">If verification fails, contains the reason.</param>
        /// <returns>True if the server is the expected KeePass process, false otherwise.</returns>
        public static bool VerifyServer(SafePipeHandle pipeHandle, out string reason)
        {
            reason = null;
            try
            {
                if (!GetNamedPipeServerProcessId(pipeHandle, out uint serverPid))
                {
                    reason = "Failed to get server process ID";
                    return false;
                }

                string imagePath = GetProcessImagePath(serverPid);
                if (imagePath == null)
                {
                    reason = "Failed to get server process image path";
                    return false;
                }

                string fileName = Path.GetFileName(imagePath);
                if (!string.Equals(fileName, ExpectedServerImage, StringComparison.OrdinalIgnoreCase))
                {
                    reason = $"Unexpected server process: {fileName}";
                    return false;
                }

                var signatureValidator = PluginSignatureValidator;
                if (signatureValidator != null)
                {
                    string sigReason = signatureValidator(serverPid);
                    if (sigReason != null)
                    {
                        reason = sigReason;
                        return false;
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                reason = $"Verification error: {ex.Message}";
                return false;
            }
        }

        private static string GetProcessImagePath(uint pid)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
                return null;
            try
            {
                int capacity = 1024;
                var sb = new StringBuilder(capacity);
                if (!QueryFullProcessImageName(hProcess, 0, sb, ref capacity))
                    return null;
                return sb.ToString(0, capacity);
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        #region Native methods

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle Pipe, out uint ServerProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref int lpdwSize);

        #endregion
    }
}
