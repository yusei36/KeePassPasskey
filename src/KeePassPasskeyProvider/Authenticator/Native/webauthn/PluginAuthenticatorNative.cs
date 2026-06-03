// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace KeePassPasskeyProvider.Authenticator.Native;

// =============================================================================
// Complete managed transcription of pluginauthenticator.h: the IPluginAuthenticator
// COM interface contract and its operation request/response structures. These types
// are NOT in the shipped Win32 winmd, so they are bound by hand.
//
// pluginauthenticator.h declares no exported C functions - only the COM interface
// (consumed via vtable in PluginAuthenticator.cs) and its supporting structs/enums.
// The WebAuthNPlugin* management APIs live in WebAuthnPluginNative.cs; the WebAuthN
// data types live in WebAuthnNative.cs.
//
// Source: https://github.com/microsoft/webauthn (pluginauthenticator.h, pluginauthenticator.idl).
// Transcribed from commit 273689d1d542 (2026-01-10) on 2026-06-03.
// Those headers are Copyright (c) Microsoft Corporation, licensed under the MIT
// License; the full MIT notice ships in THIRD_PARTY_NOTICES.txt.
//
// Same ABI conventions as WebAuthnNative.cs (x64, natural alignment, DWORD->uint,
// GUID inline, HWND->nint).
// =============================================================================

#region Enums

/// <summary>PLUGIN_LOCK_STATUS.</summary>
internal enum PluginLockStatus : int
{
    PluginLocked = 0,
    PluginUnlocked = 1,
}

/// <summary>WEBAUTHN_PLUGIN_REQUEST_TYPE.</summary>
internal enum WebAuthnPluginRequestType : uint
{
    Ctap2Cbor = 1, // WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR
}

#endregion

#region Operation structures

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_REQUEST - passed in by the platform (read only).
/// Layout (x64): HWND(8) + GUID(16) + DWORD(4)+[pad] + ptr(8) + DWORD(4) + DWORD(4) + ptr(8) = 56 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationRequest
{
    public nint hWnd;                              // HWND
    public Guid transactionId;                     // 16 bytes
    public uint cbRequestSignature;
    public byte* pbRequestSignature;
    public WebAuthnPluginRequestType requestType;  // enum = DWORD
    public uint cbEncodedRequest;
    public byte* pbEncodedRequest;
}

/// <summary>
/// WEBAUTHN_PLUGIN_OPERATION_RESPONSE - written by the authenticator.
/// pbEncodedResponse is allocated by WebAuthNEncode*, owned and freed by the platform.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginOperationResponse
{
    public uint cbEncodedResponse;
    public byte* pbEncodedResponse;
}

/// <summary>WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST - passed in by the platform.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct WebAuthnPluginCancelOperationRequest
{
    public Guid transactionId;
    public uint cbRequestSignature;
    public byte* pbRequestSignature;
}

#endregion

#region COM interface identifiers

/// <summary>COM interface IIDs from pluginauthenticator.h and the COM standard.</summary>
internal static class ComIids
{
    /// <summary>IPluginAuthenticator IID (pluginauthenticator.h MIDL_INTERFACE).</summary>
    public static readonly Guid IID_IPluginAuthenticator = new("d26bcf6f-b54c-43ff-9f06-d5bf148625f7");

    /// <summary>IClassFactory IID (standard COM).</summary>
    public static readonly Guid IID_IClassFactory = new("00000001-0000-0000-C000-000000000046");

    /// <summary>IUnknown IID (standard COM).</summary>
    public static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");
}

#endregion
