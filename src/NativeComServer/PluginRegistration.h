#pragma once
#include "pch.h"

// KeePassXC-compatible AAGUID: fdb141b2-5d84-443e-8a35-4698c205a502
// {fdb141b2-5d84-443e-8a35-4698c205a502}
static constexpr CLSID KEEPASS_PASSKEY_PLUGIN_CLSID = {
    0xfdb141b2, 0x5d84, 0x443e,
    { 0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02 }
};

static constexpr WCHAR PluginName[]    = L"KeePass Passkey Provider";
static constexpr WCHAR PluginRpId[]    = L"keepass.info";
static constexpr WCHAR PluginRegPath[] = L"Software\\KeePassPasskeyProvider";
static constexpr WCHAR RegKeySigningKey[] = L"OpSigningPublicKey";

/// Build the authenticatorGetInfo CBOR blob for registration.
/// Format matches the Contoso sample:
/// {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["prf", "hmac-secret"],
///  3: h'<AAGUID>', 4: {"rk": true, "up": true, "uv": true},
///  9: ["internal"], 10: [{"alg": -7, "type": "public-key"}]}
std::vector<BYTE> BuildAuthenticatorInfoCbor();

/// Register this plugin with the Windows passkey platform.
/// Stores the returned operation signing public key in the registry.
HRESULT RegisterPlugin();

/// Unregister this plugin.
HRESULT UnregisterPlugin();

/// Query whether the plugin is enabled in Windows Settings.
HRESULT GetPluginState(AUTHENTICATOR_STATE& state);

/// Load the stored operation signing public key from registry.
bool LoadSigningPublicKey(std::vector<BYTE>& keyBlob);
