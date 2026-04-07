#include "pch.h"
#include "PipeClient.h"

bool PipeClient::SendRequest(const std::string& requestJson, std::string& responseJson)
{
    // Wait up to 2 seconds for the pipe to become available
    if (!WaitNamedPipeW(PipeName, 2000))
        return false;

    HANDLE hPipe = CreateFileW(
        PipeName,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING,
        0, nullptr);

    if (hPipe == INVALID_HANDLE_VALUE)
        return false;

    // Set to message/byte mode
    DWORD dwMode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &dwMode, nullptr, nullptr);

    bool ok = WriteMessage(hPipe, requestJson) && ReadMessage(hPipe, responseJson);
    CloseHandle(hPipe);
    return ok;
}

bool PipeClient::WriteMessage(HANDLE hPipe, const std::string& json)
{
    // Length prefix: 4-byte LE uint32
    DWORD length = static_cast<DWORD>(json.size());
    DWORD written = 0;

    if (!WriteFile(hPipe, &length, 4, &written, nullptr) || written != 4)
        return false;
    if (!WriteFile(hPipe, json.data(), length, &written, nullptr) || written != length)
        return false;
    return true;
}

bool PipeClient::ReadMessage(HANDLE hPipe, std::string& json)
{
    DWORD length = 0;
    DWORD bytesRead = 0;

    if (!ReadFile(hPipe, &length, 4, &bytesRead, nullptr) || bytesRead != 4)
        return false;
    if (length == 0 || length > 1024 * 1024)
        return false;

    std::string buf(length, '\0');
    DWORD totalRead = 0;
    while (totalRead < length)
    {
        if (!ReadFile(hPipe, buf.data() + totalRead, length - totalRead, &bytesRead, nullptr))
            return false;
        totalRead += bytesRead;
    }
    json = std::move(buf);
    return true;
}
