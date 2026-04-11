using KeePassPasskeyProvider.Plugin;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace KeePassPasskeyProvider.Interop;

// ---------------------------------------------------------------------------
// IPluginAuthenticator COM interface (IID: d26bcf6f-b54c-43ff-9f06-d5bf148625f7)
// Declared as a C# interface so Marshal.GetComInterfaceForObject can produce
// a CCW with the correct vtable ordering.  Methods use nint for struct
// pointers to stay safely out of the COM marshalling machinery.
// ---------------------------------------------------------------------------

[ComVisible(true)]
[Guid("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IPluginAuthenticator
{
    [PreserveSig]
    int MakeCredential(nint pRequest, nint pResponse);

    [PreserveSig]
    int GetAssertion(nint pRequest, nint pResponse);

    [PreserveSig]
    int CancelOperation(nint pCancelRequest);

    [PreserveSig]
    int GetLockStatus(nint pLockStatus);
}

// ---------------------------------------------------------------------------
// IClassFactory COM interface (IID: 00000001-0000-0000-C000-000000000046)
// ---------------------------------------------------------------------------

[ComVisible(true)]
[Guid("00000001-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IClassFactory
{
    [PreserveSig]
    int CreateInstance(nint pUnkOuter, in Guid riid, out nint ppvObject);

    [PreserveSig]
    int LockServer([MarshalAs(UnmanagedType.Bool)] bool fLock);
}

// ---------------------------------------------------------------------------
// COM registration helpers
// ---------------------------------------------------------------------------

internal static class ComRegistration
{
    /// <summary>
    /// Registers the PluginAuthenticatorClassFactory with the COM infrastructure.
    /// Returns the DWORD cookie to pass to CoRevokeClassObject on shutdown.
    /// </summary>
    internal static uint RegisterClassFactory(ClassFactory factory)
    {
        nint factoryPtr = Marshal.GetComInterfaceForObject<ClassFactory, IClassFactory>(factory);
        try
        {
            int hr = Win32Native.CoRegisterClassObject(
                in PluginConstants.KeePassClsid,
                factoryPtr,
                Win32Native.CLSCTX_LOCAL_SERVER,
                Win32Native.REGCLS_MULTIPLEUSE,
                out uint cookie);

            if (hr < 0)
                Marshal.ThrowExceptionForHR(hr);

            return cookie;
        }
        finally
        {
            // Release our reference; COM holds its own reference until CoRevokeClassObject.
            Marshal.Release(factoryPtr);
        }
    }

    internal static void RevokeClassFactory(uint cookie)
    {
        Win32Native.CoRevokeClassObject(cookie);
    }
}
