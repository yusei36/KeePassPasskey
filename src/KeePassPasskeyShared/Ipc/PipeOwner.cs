// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace KeePassPasskeyShared.Ipc;

/// <summary>Checks the owner of the pipe a client connected to.</summary>
public static class PipeOwner
{
	private static readonly SecurityIdentifier CurrentUser = WindowsIdentity.GetCurrent().User;

	public static bool IsAccepted(SecurityIdentifier owner) => owner == CurrentUser;

	/// <summary>Reads the owner of the pipe behind <paramref name="handle"/>; null with a reason if unreadable.</summary>
	public static SecurityIdentifier Get(SafePipeHandle handle, out string error)
	{
		error = null;
		int result = GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
			out IntPtr owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IntPtr descriptor);
		if (result != 0)
		{
			error = $"GetSecurityInfo failed with error {result}";
			return null;
		}
		try
		{
			return new SecurityIdentifier(owner);
		}
		finally
		{
			LocalFree(descriptor);
		}
	}

	private const int SE_KERNEL_OBJECT = 6;
	private const uint OWNER_SECURITY_INFORMATION = 0x1;

	[DllImport("advapi32.dll")]
	private static extern int GetSecurityInfo(SafeHandle handle, int objectType, uint securityInfo,
		out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr securityDescriptor);

	[DllImport("kernel32.dll")]
	private static extern IntPtr LocalFree(IntPtr hMem);
}
