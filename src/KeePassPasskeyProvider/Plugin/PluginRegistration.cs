using System.Formats.Cbor;
using Microsoft.Win32;
using KeePassPasskeyProvider.Interop;
using KeePassPasskeyProvider.Util;

namespace KeePassPasskeyProvider.Plugin;

/// <summary>
/// Manages registration/unregistration of the plugin with the Windows passkey platform.
/// </summary>
internal static unsafe class PluginRegistration
{
    /// <summary>
    /// Builds the CTAP2 authenticatorGetInfo CBOR blob.
    /// Format: {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["prf", "hmac-secret"],
    ///          3: h'AAGUID', 4: {rk:true,up:true,uv:true},
    ///          9: ["internal"], 10: [{alg:-7,type:"public-key"}]}
    /// AAGUID is in RFC 4122 big-endian byte order: fdb141b2-5d84-443e-8a35-4698c205a502.
    /// </summary>
    public static byte[] BuildAuthenticatorInfoCbor()
    {
        // AAGUID in big-endian (RFC 4122 order), distinct from Windows GUID byte order
        ReadOnlySpan<byte> aaguid = [
            0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e,
            0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02
        ];

        var writer = new CborWriter(CborConformanceMode.Canonical, convertIndefiniteLengthEncodings: true);

        writer.WriteStartMap(6); // map with 6 entries

        // 1: versions ["FIDO_2_0", "FIDO_2_1"]
        writer.WriteInt32(1);
        writer.WriteStartArray(2);
        writer.WriteTextString("FIDO_2_0");
        writer.WriteTextString("FIDO_2_1");
        writer.WriteEndArray();

        // 2: extensions ["prf", "hmac-secret"]
        writer.WriteInt32(2);
        writer.WriteStartArray(2);
        writer.WriteTextString("prf");
        writer.WriteTextString("hmac-secret");
        writer.WriteEndArray();

        // 3: aaguid (16-byte bstr)
        writer.WriteInt32(3);
        writer.WriteByteString(aaguid);

        // 4: options {rk:true, up:true, uv:true}
        writer.WriteInt32(4);
        writer.WriteStartMap(3);
        writer.WriteTextString("rk"); writer.WriteBoolean(true);
        writer.WriteTextString("up"); writer.WriteBoolean(true);
        writer.WriteTextString("uv"); writer.WriteBoolean(true);
        writer.WriteEndMap();

        // 9: transports ["internal"]
        writer.WriteInt32(9);
        writer.WriteStartArray(1);
        writer.WriteTextString("internal");
        writer.WriteEndArray();

        // 10: algorithms [{alg:-7, type:"public-key"}]
        writer.WriteInt32(10);
        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteTextString("alg");  writer.WriteInt32(-7);
        writer.WriteTextString("type"); writer.WriteTextString("public-key");
        writer.WriteEndMap();
        writer.WriteEndArray();

        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>Registers the plugin with the Windows passkey platform.</summary>
    public static int Register()
    {
        Log.Info("entry");
        byte[] authenticatorInfo = BuildAuthenticatorInfoCbor();
        Log.Info($"CBOR blob {authenticatorInfo.Length} bytes");

        Guid clsid = PluginConstants.KeePassClsid;

        fixed (char* namePtr  = PluginConstants.PluginName)
        fixed (char* rpIdPtr  = PluginConstants.PluginRpId)
        fixed (byte* infoPtr  = authenticatorInfo)
        {
            var options = new WebAuthnPluginAddAuthenticatorOptions
            {
                pwszAuthenticatorName  = namePtr,
                rclsid                 = &clsid,
                pwszPluginRpId         = rpIdPtr,
                pwszLightThemeLogoSvg  = null,
                pwszDarkThemeLogoSvg   = null,
                cbAuthenticatorInfo    = (uint)authenticatorInfo.Length,
                pbAuthenticatorInfo    = infoPtr,
                cSupportedRpIds        = 0,
                ppwszSupportedRpIds    = null,
            };

            WebAuthnPluginAddAuthenticatorResponse* pResponse = null;
            int hr = WebAuthnPluginApi.WebAuthNPluginAddAuthenticator(&options, &pResponse);
            if (hr < 0) 
            { 
                Log.Error($"WebAuthNPluginAddAuthenticator failed hr=0x{hr:X8}"); 
                return hr;
            }
            Log.Info($"WebAuthNPluginAddAuthenticator hr=0x{hr:X8}");

            try
            {
                // Persist the operation signing public key in the registry
                if (pResponse != null && pResponse->cbOpSignPubKey > 0)
                {
                    byte[] keyBlob = new ReadOnlySpan<byte>(
                        pResponse->pbOpSignPubKey, (int)pResponse->cbOpSignPubKey).ToArray();

                    using RegistryKey? hkcu = Registry.CurrentUser;
                    using RegistryKey? key = hkcu?.CreateSubKey(PluginConstants.PluginRegPath, writable: true);
                    key?.SetValue(PluginConstants.RegKeySigningKey, keyBlob, RegistryValueKind.Binary);
                    Log.Info($"stored signing key {keyBlob.Length} bytes");
                }
            }
            finally
            {
                WebAuthnPluginApi.WebAuthNPluginFreeAddAuthenticatorResponse(pResponse);
            }
        }

        Log.Info("success");
        return 0; // S_OK
    }

    /// <summary>Unregisters the plugin from the Windows passkey platform.</summary>
    public static int Unregister()
    {
        Log.Info("entry");
        int hr = WebAuthnPluginApi.WebAuthNPluginRemoveAuthenticator(PluginConstants.KeePassClsid);
        Log.Info($"hr=0x{hr:X8}");
        return hr;
    }

    /// <summary>Queries whether the plugin is enabled in Windows Settings.</summary>
    public static int GetState(out AuthenticatorState state)
    {
        state = AuthenticatorState.AuthenticatorState_Disabled;
        int hr = WebAuthnPluginApi.WebAuthNPluginGetAuthenticatorState(
            PluginConstants.KeePassClsid, (AuthenticatorState*)System.Runtime.CompilerServices.Unsafe.AsPointer(ref state));
        Log.Info($"hr=0x{hr:X8} state={state}");
        return hr;
    }
}
