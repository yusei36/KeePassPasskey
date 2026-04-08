#include "pch.h"
#include "PluginRegistration.h"
#include "Log.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

static std::string HexStringFromBytes(const BYTE* pb, size_t cb)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < cb; ++i)
        ss << std::setw(2) << static_cast<unsigned>(pb[i]);
    return ss.str();
}

static std::vector<BYTE> HexStringToBytes(const std::string& hex)
{
    std::vector<BYTE> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        BYTE b = static_cast<BYTE>(std::stoul(hex.substr(i, 2), nullptr, 16));
        result.push_back(b);
    }
    return result;
}

std::vector<BYTE> BuildAuthenticatorInfoCbor()
{
    // AAGUID bytes for fdb141b2-5d84-443e-8a35-4698c205a502
    // Note: GUID wire encoding — first 3 fields are little-endian on Windows
    // but for FIDO the AAGUID is always big-endian (RFC 4122 UUID bytes)
    const BYTE aaguid[16] = {
        0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e,
        0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02
    };
    std::string aaguidHex = HexStringFromBytes(aaguid, 16);

    // CBOR template from PasskeyManager sample (pre-encoded with AAGUID slot)
    std::string part1 = "A60182684649444F5F325F30684649444F5F325F310282637072666B686D61632D7365637265740350";
    std::string part2 = "04A362726BF5627570F5627576F5098168696E7465726E616C0A81A263616C672664747970656A7075626C69632D6B6579";
    std::string fullHex = part1 + aaguidHex + part2;
    return HexStringToBytes(fullHex);
}

HRESULT RegisterPlugin()
{
    Log("RegisterPlugin: entry");
    auto authenticatorInfo = BuildAuthenticatorInfoCbor();

    WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS options{
        .pwszAuthenticatorName  = PluginName,
        .rclsid                 = KEEPASS_PASSKEY_PLUGIN_CLSID,
        .pwszPluginRpId         = PluginRpId,
        .pwszLightThemeLogoSvg  = nullptr,
        .pwszDarkThemeLogoSvg   = nullptr,
        .cbAuthenticatorInfo    = static_cast<DWORD>(authenticatorInfo.size()),
        .pbAuthenticatorInfo    = authenticatorInfo.data(),
        .cSupportedRpIds        = 0,
        .ppwszSupportedRpIds    = nullptr,
    };

    PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE pResponse = nullptr;
    HRESULT hr = WebAuthNPluginAddAuthenticator(&options, &pResponse);
    Log("RegisterPlugin: WebAuthNPluginAddAuthenticator hr=0x%08X", hr);
    RETURN_IF_FAILED(hr);
    auto cleanup = wil::scope_exit([&] { WebAuthNPluginFreeAddAuthenticatorResponse(pResponse); });

    // Store operation signing public key in registry
    wil::unique_hkey hKey;
    LONG lReg = RegCreateKeyExW(
        HKEY_CURRENT_USER, PluginRegPath, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    Log("RegisterPlugin: RegCreateKeyEx result=%ld", lReg);
    RETURN_IF_WIN32_ERROR(lReg);

    lReg = RegSetValueExW(
        hKey.get(), RegKeySigningKey, 0, REG_BINARY,
        pResponse->pbOpSignPubKey, pResponse->cbOpSignPubKey);
    Log("RegisterPlugin: RegSetValueEx result=%ld cbSigningKey=%u", lReg, pResponse->cbOpSignPubKey);
    RETURN_IF_WIN32_ERROR(lReg);

    Log("RegisterPlugin: success");
    return S_OK;
}

HRESULT UnregisterPlugin()
{
    Log("UnregisterPlugin: entry");
    HRESULT hr = WebAuthNPluginRemoveAuthenticator(KEEPASS_PASSKEY_PLUGIN_CLSID);
    Log("UnregisterPlugin: WebAuthNPluginRemoveAuthenticator hr=0x%08X", hr);
    return hr;
}

HRESULT GetPluginState(AUTHENTICATOR_STATE& state)
{
    return WebAuthNPluginGetAuthenticatorState(KEEPASS_PASSKEY_PLUGIN_CLSID, &state);
}

bool LoadSigningPublicKey(std::vector<BYTE>& keyBlob)
{
    wil::unique_hkey hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, PluginRegPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD cbData = 0;
    if (RegQueryValueExW(hKey.get(), RegKeySigningKey, nullptr, nullptr, nullptr, &cbData) != ERROR_SUCCESS)
        return false;

    keyBlob.resize(cbData);
    if (RegQueryValueExW(hKey.get(), RegKeySigningKey, nullptr, nullptr, keyBlob.data(), &cbData) != ERROR_SUCCESS)
        return false;

    keyBlob.resize(cbData);
    return true;
}
