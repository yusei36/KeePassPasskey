#pragma once
#include <string>
#include <vector>
#include <stdexcept>

/// Minimal JSON builder/parser for the KeePass passkey IPC protocol.
/// Values are base64 strings and string arrays — no general-purpose parser needed.
namespace JsonHelper
{
    /// Escape a string for JSON embedding
    inline std::string Escape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s)
        {
            if (c == '"')  { out += "\\\""; }
            else if (c == '\\') { out += "\\\\"; }
            else if (c == '\n') { out += "\\n"; }
            else if (c == '\r') { out += "\\r"; }
            else { out += c; }
        }
        return out;
    }

    /// Escape a wide string (convert to UTF-8 first)
    inline std::string EscapeW(const wchar_t* wsz)
    {
        if (!wsz) return "";
        int len = WideCharToMultiByte(CP_UTF8, 0, wsz, -1, nullptr, 0, nullptr, nullptr);
        std::string utf8(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wsz, -1, utf8.data(), len, nullptr, nullptr);
        if (!utf8.empty() && utf8.back() == '\0') utf8.pop_back();
        return Escape(utf8);
    }

    /// Build a JSON string array from a vector
    inline std::string StringArray(const std::vector<std::string>& items)
    {
        std::string out = "[";
        for (size_t i = 0; i < items.size(); ++i)
        {
            if (i > 0) out += ",";
            out += "\"" + Escape(items[i]) + "\"";
        }
        out += "]";
        return out;
    }

    /// Extract a string field value from JSON {"field":"value",...}
    /// Returns empty string if not found.
    inline std::string GetStringField(const std::string& json, const std::string& field)
    {
        std::string key = "\"" + field + "\":\"";
        auto pos = json.find(key);
        if (pos == std::string::npos) return {};
        pos += key.size();
        auto end = json.find('"', pos);
        if (end == std::string::npos) return {};
        return json.substr(pos, end - pos);
    }

    /// Check if the response has "type":"error"
    inline bool IsError(const std::string& json)
    {
        return json.find("\"type\":\"error\"") != std::string::npos;
    }

    /// Get error code from response
    inline std::string GetErrorCode(const std::string& json)
    {
        return GetStringField(json, "code");
    }

    /// Base64 decode (standard, not URL-safe)
    inline std::vector<BYTE> Base64Decode(const std::string& b64)
    {
        if (b64.empty()) return {};
        DWORD cbBinary = 0;
        CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, nullptr, &cbBinary, nullptr, nullptr);
        std::vector<BYTE> out(cbBinary);
        CryptStringToBinaryA(b64.c_str(), static_cast<DWORD>(b64.size()),
            CRYPT_STRING_BASE64, out.data(), &cbBinary, nullptr, nullptr);
        out.resize(cbBinary);
        return out;
    }

    /// Base64 encode (standard)
    inline std::string Base64Encode(const BYTE* pb, DWORD cb)
    {
        DWORD cchString = 0;
        CryptBinaryToStringA(pb, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cchString);
        std::string out(cchString, '\0');
        CryptBinaryToStringA(pb, cb, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &cchString);
        while (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    /// Base64url decode: replace - with + and _ with /
    inline std::vector<BYTE> Base64UrlDecode(const std::string& b64url)
    {
        std::string s = b64url;
        for (char& c : s) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
        switch (s.size() % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Base64Decode(s);
    }
}

#pragma comment(lib, "crypt32.lib")
