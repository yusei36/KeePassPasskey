using Microsoft.Win32;
using KeePassPasskeyProvider.Authenticator.Native;
using KeePassPasskeyShared;
using PeterO.Cbor;

namespace KeePassPasskeyProvider.Authenticator;

/// <summary>
/// Manages registration/unregistration of the plugin with the Windows passkey platform.
/// </summary>
internal static unsafe class PluginRegistration
{
    /// <summary>
    /// Ensures the plugin is registered and the signing key is present.
    /// Re-registers if the key is missing. Returns false if registration failed.
    /// </summary>
    public static bool EnsureRegistered()
    {
        int stateHr = GetState(out _);
        if (stateHr >= 0)
        {
            if (SignatureVerifier.LoadSigningPublicKey() != null) return true;

#if DEBUG
            Log.Warn("registered but signing key missing, allowing operations for development");
            return true;
#else
            Log.Warn("registered but signing key missing, re-registering");
            Unregister();
#endif
        }

        int hr = Register();
        if (hr < 0) Log.Error($"auto-registration failed hr=0x{hr:X8}");
        return hr >= 0;
    }

    /// <summary>Registers the plugin with the Windows passkey platform.</summary>
    public static int Register()
    {
        Log.Info("entry");
        byte[] authenticatorInfo = BuildAuthenticatorInfoCbor();
        Log.Info($"CBOR blob {authenticatorInfo.Length} bytes");

        Guid clsid = PluginConstants.KeePassPasskeyProviderClsid;

        string lightSvg = LogoResources.LightThemeSvg;
        string darkSvg  = LogoResources.DarkThemeSvg;

        fixed (char* namePtr     = PluginConstants.PluginName)
        fixed (char* rpIdPtr     = PluginConstants.PluginRpId)
        fixed (byte* infoPtr     = authenticatorInfo)
        fixed (char* lightSvgPtr = lightSvg)
        fixed (char* darkSvgPtr  = darkSvg)
        {
            var options = new WebAuthnPluginAddAuthenticatorOptions
            {
                pwszAuthenticatorName  = namePtr,
                rclsid                 = &clsid,
                pwszPluginRpId         = rpIdPtr,
                pwszLightThemeLogoSvg  = lightSvgPtr,
                pwszDarkThemeLogoSvg   = darkSvgPtr,
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
        int hr = WebAuthnPluginApi.WebAuthNPluginRemoveAuthenticator(PluginConstants.KeePassPasskeyProviderClsid);
        Log.Info($"hr=0x{hr:X8}");
        return hr;
    }

    /// <summary>Queries whether the plugin is enabled in Windows Settings.</summary>
    public static int GetState(out AuthenticatorState state)
    {
        state = AuthenticatorState.AuthenticatorState_Disabled;
        int hr = WebAuthnPluginApi.WebAuthNPluginGetAuthenticatorState(
            PluginConstants.KeePassPasskeyProviderClsid, (AuthenticatorState*)System.Runtime.CompilerServices.Unsafe.AsPointer(ref state));
        Log.Info($"hr=0x{hr:X8} state={state}");
        return hr;
    }

    /// <summary>
    /// Builds the CTAP2 authenticatorGetInfo CBOR blob.
    /// Format: {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["prf", "hmac-secret"],
    ///          3: h'AAGUID', 4: {rk:true,up:true,uv:true},
    ///          9: ["internal"], 10: [{alg:-7,type:"public-key"},{alg:-8,...},{alg:-257,...}]}
    /// Keys sorted per CTAP2 canonical ordering.
    /// </summary>
    private static byte[] BuildAuthenticatorInfoCbor()
    {
        var encodeOptions = new CBOREncodeOptions("ctap2canonical=true");
        var info = CBORObject.NewMap();

        // 1: versions
        info.Add(1, CBORObject.NewArray().Add("FIDO_2_0").Add("FIDO_2_1"));

        // 2: extensions
        info.Add(2, CBORObject.NewArray().Add("prf").Add("hmac-secret"));

        // 3: aaguid (16-byte bstr)
        info.Add(3, PluginConstants.KeePassPasskeyProviderAaguidBytes);

        // 4: options {rk:true, up:true, uv:true}
        info.Add(4, CBORObject.NewMap().Add("rk", true).Add("up", true).Add("uv", true));

        // 9: transports
        info.Add(9, CBORObject.NewArray().Add("internal"));

        // 10: algorithms — ES256, EdDSA, RS256
        var algorithms = CBORObject.NewArray();
        algorithms.Add(CBORObject.NewMap().Add("alg", -7).Add("type", "public-key"));
        algorithms.Add(CBORObject.NewMap().Add("alg", -8).Add("type", "public-key"));
        algorithms.Add(CBORObject.NewMap().Add("alg", -257).Add("type", "public-key"));
        info.Add(10, algorithms);

        return info.EncodeToBytes(encodeOptions);
    }
}
