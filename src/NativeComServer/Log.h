#pragma once
#include <cstdio>
#include <cstdarg>

inline void Log(const char* fmt, ...)
{
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wchar_t logPath[MAX_PATH];
    wsprintfW(logPath, L"%sPasskeyProvider.log", tempPath);

    FILE* f = nullptr;
    _wfopen_s(&f, logPath, L"a");
    if (!f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fprintf(f, "\n");
    fclose(f);
}
