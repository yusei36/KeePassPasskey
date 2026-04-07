#pragma once
#include "pch.h"
#include <string>
#include <vector>

/// Simple synchronous named pipe client.
/// Each call opens the pipe, sends a request, reads the response, closes.
class PipeClient
{
public:
    static constexpr WCHAR PipeName[] = L"\\\\.\\pipe\\keepass-passkey-provider";

    /// Send JSON request, receive JSON response.
    /// Returns false if the pipe is unavailable (KeePass not running).
    static bool SendRequest(const std::string& requestJson, std::string& responseJson);

private:
    static bool WriteMessage(HANDLE hPipe, const std::string& json);
    static bool ReadMessage(HANDLE hPipe, std::string& json);
};
