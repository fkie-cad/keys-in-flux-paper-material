// Minimal x64dbg plugin
#include <cstring>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include "pluginmain.h"

// Global state for CSV logging
static std::ofstream csvFile;
static std::string csvFilePath;
static int currentSessionId = 1;
static bool csvFileOpen = false;

// Global variables required by the plugin framework
int pluginHandle = 0;
HWND hwndDlg = 0;
int hMenu = 0;
int hMenuDisasm = 0;
int hMenuDump = 0;
int hMenuStack = 0;
int hMenuGraph = 0;
int hMenuMemmap = 0;
int hMenuSymmod = 0;

// Create CSV file in temp directory
static bool createCSVFile()
{
    if (csvFileOpen)
    {
        _plugin_logprintf("[%s] CSV file already open\n", PLUGIN_NAME);
        return true;
    }

    // Get temp directory
    char tempPath[MAX_PATH];
    DWORD result = GetTempPathA(MAX_PATH, tempPath);
    if (result == 0)
    {
        _plugin_logprintf("[%s] Failed to get temp directory\n", PLUGIN_NAME);
        return false;
    }

    // Always use the same filename: timing_13.csv
    std::ostringstream filename;
    filename << tempPath << "timing_13.csv";
    csvFilePath = filename.str();

    // Check if file already exists
    bool fileExists = false;
    std::ifstream checkFile(csvFilePath);
    if (checkFile.good())
    {
        fileExists = true;
        checkFile.close();
    }

    // Open CSV file in append mode
    csvFile.open(csvFilePath, std::ios::out | std::ios::app);
    if (!csvFile.is_open())
    {
        _plugin_logprintf("[%s] Failed to open CSV file: %s\n", PLUGIN_NAME, csvFilePath.c_str());
        return false;
    }

    // Write CSV header only if file is new
    if (!fileExists)
    {
        csvFile << "ID,timestamp,label,secret\n";
        csvFile.flush();  // Ensure header is written immediately
        _plugin_logprintf("[%s] New CSV file created: %s\n", PLUGIN_NAME, csvFilePath.c_str());
    }
    else
    {
        _plugin_logprintf("[%s] Existing CSV file opened: %s\n", PLUGIN_NAME, csvFilePath.c_str());
    }

    csvFileOpen = true;
    return true;
}

// Close CSV file and increment session ID
static bool closeCSVFile()
{
    if (!csvFileOpen)
    {
        _plugin_logprintf("[%s] No CSV file open\n", PLUGIN_NAME);
        return false;
    }

    csvFile.close();
    csvFileOpen = false;
    currentSessionId++;
    
    _plugin_logprintf("[%s] CSV file closed. Next session ID: %d\n", PLUGIN_NAME, currentSessionId);
    _plugin_logprintf("[%s] All future entries will use ID %d\n", PLUGIN_NAME, currentSessionId);
    return true;
}

// Simple test command
static bool cb_test(int argc, char* argv[])
{
    _plugin_logprintf("[%s] Test command executed successfully!\n", PLUGIN_NAME);
    return true;
}

// Command to create CSV file
static bool cb_create_csv(int argc, char* argv[])
{
    if (createCSVFile())
    {
        _plugin_logprintf("[%s] CSV file created successfully\n", PLUGIN_NAME);
        return true;
    }
    else
    {
        _plugin_logprintf("[%s] Failed to create CSV file\n", PLUGIN_NAME);
        return false;
    }
}

// Command to close CSV file
static bool cb_close_csv(int argc, char* argv[])
{
    if (closeCSVFile())
    {
        _plugin_logprintf("[%s] CSV file closed successfully\n", PLUGIN_NAME);
        return true;
    }
    else
    {
        _plugin_logprintf("[%s] Failed to close CSV file\n", PLUGIN_NAME);
        return false;
    }
}

// Get timestamp as string for scripts
static std::string getTimestampString()
{
    FILETIME ftUtc;
    GetSystemTimePreciseAsFileTime(&ftUtc);
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    SYSTEMTIME st;
    FileTimeToSystemTime(&ftLocal, &st);

    ULARGE_INTEGER uli;
    uli.LowPart = ftLocal.dwLowDateTime;
    uli.HighPart = ftLocal.dwHighDateTime;
    unsigned long long ticks100ns = uli.QuadPart;
    unsigned long long microseconds = (ticks100ns % 10000000ULL) / 10ULL;
    unsigned int ms = (unsigned int)(microseconds / 1000);
    unsigned int us = (unsigned int)(microseconds % 1000);

    char timestamp[80];
    sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d%03d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, ms, us);

    return std::string(timestamp);
}

// Get timestamp as microseconds since epoch for scripts
static unsigned long long getTimestampMicros()
{
    FILETIME ftUtc;
    GetSystemTimePreciseAsFileTime(&ftUtc);
    
    ULARGE_INTEGER uli;
    uli.LowPart = ftUtc.dwLowDateTime;
    uli.HighPart = ftUtc.dwHighDateTime;
    
    // Convert from 100ns ticks since 1601 to microseconds since 1970 (Unix epoch)
    // 1601 to 1970 is 11644473600 seconds = 116444736000000000 * 100ns ticks
    const unsigned long long EPOCH_DIFF = 116444736000000000ULL;
    unsigned long long ticks100ns = uli.QuadPart - EPOCH_DIFF;
    unsigned long long microseconds = ticks100ns / 10ULL;
    
    return microseconds;
}

// Command to get timestamp string for scripts
static bool cb_get_timestamp(int argc, char* argv[])
{
    std::string timestamp = getTimestampString();
    
    // For string values, we need to use a different approach
    // We'll store it as a comment or use log output that scripts can parse
    _plugin_logprintf("[%s] TIMESTAMP_RESULT: %s\n", PLUGIN_NAME, timestamp.c_str());
    
    return true;
}

// Command to get timestamp as microseconds for scripts
static bool cb_get_timestamp_micros(int argc, char* argv[])
{
    unsigned long long micros = getTimestampMicros();
    
    // Set the result variable that scripts can access (numeric value works)
    DbgValToString("$result", (duint)micros);
    
    _plugin_logprintf("[%s] Timestamp (microseconds): %llu (stored in $result)\n", PLUGIN_NAME, micros);
    return true;
}

// Command to write a test entry to CSV
static bool cb_write_test(int argc, char* argv[])
{
    if (!csvFileOpen)
    {
        _plugin_logprintf("[%s] CSV file not open. Use 'createcsv' first\n", PLUGIN_NAME);
        return false;
    }

    // Get current timestamp
    FILETIME ftUtc;
    GetSystemTimePreciseAsFileTime(&ftUtc);
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    SYSTEMTIME st;
    FileTimeToSystemTime(&ftLocal, &st);

    ULARGE_INTEGER uli;
    uli.LowPart = ftLocal.dwLowDateTime;
    uli.HighPart = ftLocal.dwHighDateTime;
    unsigned long long ticks100ns = uli.QuadPart;
    unsigned long long microseconds = (ticks100ns % 10000000ULL) / 10ULL;
    unsigned int ms = (unsigned int)(microseconds / 1000);
    unsigned int us = (unsigned int)(microseconds % 1000);

    char timestamp[80];
    sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d%03d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, ms, us);

    // Write test entry with current session ID
    csvFile << currentSessionId << "," << timestamp << ",test_entry,sample_secret\n";
    csvFile.flush();

    _plugin_logprintf("[%s] Test entry written to CSV with ID %d\n", PLUGIN_NAME, currentSessionId);
    return true;
}

// Convert hex string to readable format
static std::string formatHexString(const std::string& hexStr)
{
    std::string result;
    for (size_t i = 0; i < hexStr.length(); i += 2)
    {
        if (i + 1 < hexStr.length())
        {
            if (i > 0) result += " ";
            result += hexStr.substr(i, 2);
        }
    }
    return result;
}

// Logging API: log timestamp, label, and byte string to CSV
// Usage: logentry label,hex_bytes[,custom_timestamp]
static bool cb_log_entry(int argc, char* argv[])
{
    if (!csvFileOpen)
    {
        _plugin_logprintf("[%s] CSV file not open. Use 'createcsv' first\n", PLUGIN_NAME);
        return false;
    }

    if (argc < 3)
    {
        _plugin_logprintf("[%s] Usage: logentry label,hex_bytes[,custom_timestamp]\n", PLUGIN_NAME);
        _plugin_logprintf("[%s] Example: logentry start_function,48894C2408\n", PLUGIN_NAME);
        return false;
    }

    std::string label = argv[1] ? argv[1] : "unknown";
    std::string hexBytes = argv[2] ? argv[2] : "";
    std::string timestamp;

    // Use custom timestamp if provided, otherwise get current timestamp
    if (argc >= 4 && argv[3] && strlen(argv[3]) > 0)
    {
        timestamp = argv[3];
    }
    else
    {
        timestamp = getTimestampString();
    }

    // Format hex bytes for better readability
    std::string formattedHex = formatHexString(hexBytes);

    // Write entry to CSV with proper escaping for commas
    csvFile << currentSessionId << ",\"" << timestamp << "\",\"" << label << "\",\"" << formattedHex << "\"\n";
    csvFile.flush();

    _plugin_logprintf("[%s] Entry logged: ID=%d, Label=\"%s\", Bytes=\"%s\"\n", 
                     PLUGIN_NAME, currentSessionId, label.c_str(), formattedHex.c_str());
    return true;
}

// Command to get current session ID
static bool cb_get_session_id(int argc, char* argv[])
{
    DbgValToString("$result", (duint)currentSessionId);
    _plugin_logprintf("[%s] Current session ID: %d (stored in $result)\n", PLUGIN_NAME, currentSessionId);
    return true;
}

// Command to get CSV file status
static bool cb_csv_status(int argc, char* argv[])
{
    if (csvFileOpen)
    {
        _plugin_logprintf("[%s] CSV Status: OPEN\n", PLUGIN_NAME);
        _plugin_logprintf("[%s] File: %s\n", PLUGIN_NAME, csvFilePath.c_str());
        _plugin_logprintf("[%s] Session ID: %d\n", PLUGIN_NAME, currentSessionId);
    }
    else
    {
        _plugin_logprintf("[%s] CSV Status: CLOSED\n", PLUGIN_NAME);
        _plugin_logprintf("[%s] Next session ID: %d\n", PLUGIN_NAME, currentSessionId);
    }
    return true;
}

// Log memory using x64dbg variables
// Usage: logmemvars label_var,address_var,size_var[,timestamp_var]
static bool cb_logmem_vars(int argc, char* argv[])
{
    if (!csvFileOpen)
    {
        _plugin_logprintf("[%s] CSV file not open. Use 'createcsv' first\n", PLUGIN_NAME);
        return true;
    }

    if (argc < 4)
    {
        _plugin_logprintf("[%s] Usage: logmemvars label_var,address_var,size_var[,timestamp_var]\n", PLUGIN_NAME);
        _plugin_logprintf("[%s] Example: logmemvars saved_secret_kind,secret_ptr,secret_size,time_stamp\n", PLUGIN_NAME);
        return true;
    }

    // Evaluate variables using x64dbg's expression evaluator
    duint labelAddr = DbgEval(argv[1]);
    duint addressVar = DbgEval(argv[2]);
    duint sizeVar = DbgEval(argv[3]);
    duint timestampVar = 0;
    
    if (argc >= 5)
    {
        timestampVar = DbgEval(argv[4]);
    }

    _plugin_logprintf("[%s] Evaluated: label_addr=%p, address=%p, size=%zu, timestamp=%llu\n", 
                     PLUGIN_NAME, (void*)labelAddr, (void*)addressVar, sizeVar, timestampVar);

    // Read label string from memory (labelAddr should point to a string)
    char labelBuffer[256] = "unknown_label";
    if (labelAddr != 0)
    {
        if (!DbgMemRead(labelAddr, labelBuffer, sizeof(labelBuffer) - 1))
        {
            strcpy_s(labelBuffer, "read_error");
        }
        labelBuffer[sizeof(labelBuffer) - 1] = '\0';
    }

    // Validate size (reasonable limit)
    if (sizeVar == 0)
    {
        _plugin_logprintf("[%s] Size is zero\n", PLUGIN_NAME);
        return true;
    }
    
    if (sizeVar > 4096)
    {
        _plugin_logprintf("[%s] Size too large (max 4096 bytes): %zu\n", PLUGIN_NAME, sizeVar);
        return true;
    }

    // Read memory from the debugged process
    unsigned char* buffer = new unsigned char[sizeVar];
    if (!DbgMemRead(addressVar, buffer, sizeVar))
    {
        _plugin_logprintf("[%s] Failed to read memory at address %p\n", PLUGIN_NAME, (void*)addressVar);
        delete[] buffer;
        return true;
    }

    // Convert to hex string
    std::string hexData;
    for (size_t i = 0; i < sizeVar; i++)
    {
        char hexByte[4];
        sprintf_s(hexByte, "%02X", buffer[i]);
        if (i > 0) hexData += " ";
        hexData += hexByte;
    }

    // Get timestamp
    std::string timeStr;
    if (timestampVar > 0)
    {
        // Convert microseconds to formatted timestamp
        time_t seconds = timestampVar / 1000000;
        uint64_t microseconds = timestampVar % 1000000;
        
        struct tm timeinfo;
        localtime_s(&timeinfo, &seconds);
        
        char timeBuffer[64];
        sprintf_s(timeBuffer, "%04d-%02d-%02d %02d:%02d:%02d.%06llu",
                 timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                 timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, microseconds);
        timeStr = timeBuffer;
    }
    else
    {
        timeStr = getTimestampString();
    }

    // Write to CSV with proper escaping
    csvFile << currentSessionId << ","
           << "\"" << timeStr << "\","
           << "\"" << labelBuffer << "\","
           << "\"" << hexData << "\"" << std::endl;

    csvFile.flush();

    _plugin_logprintf("[%s] Memory logged from variables: ID=%d, Label=\"%s\", Address=%p, Size=%zu bytes\n", 
                     PLUGIN_NAME, currentSessionId, labelBuffer, (void*)addressVar, sizeVar);

    delete[] buffer;
    return true;
}

// Simple timestamp command
static bool cb_timestamp(int argc, char* argv[])
{
    // Get precise local time with microseconds
    FILETIME ftUtc;
    GetSystemTimePreciseAsFileTime(&ftUtc);

    // Convert to local time
    FILETIME ftLocal;
    FileTimeToLocalFileTime(&ftUtc, &ftLocal);

    // Convert to SYSTEMTIME for easy formatting
    SYSTEMTIME st;
    FileTimeToSystemTime(&ftLocal, &st);

    // Calculate microseconds from the FILETIME
    ULARGE_INTEGER uli;
    uli.LowPart = ftLocal.dwLowDateTime;
    uli.HighPart = ftLocal.dwHighDateTime;
    
    // Get microseconds within the current second
    unsigned long long ticks100ns = uli.QuadPart;
    unsigned long long microseconds = (ticks100ns % 10000000ULL) / 10ULL;
    
    // Split into milliseconds and remaining microseconds
    unsigned int ms = (unsigned int)(microseconds / 1000);
    unsigned int us = (unsigned int)(microseconds % 1000);

    char timestamp[80];
    sprintf_s(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d%03d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, ms, us);

    // Check if there's a label argument
    if (argc >= 2 && argv && argv[1] && strlen(argv[1]) > 0)
    {
        _plugin_logprintf("[%s] %s | %s\n", PLUGIN_NAME, timestamp, argv[1]);
    }
    else
    {
        _plugin_logprintf("[%s] %s\n", PLUGIN_NAME, timestamp);
    }
    
    return true;
}

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if (!initStruct)
        return false;
        
    // Set the required fields that x64dbg expects
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = PLUGIN_VERSION;
    strcpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), PLUGIN_NAME);
        
    pluginHandle = initStruct->pluginHandle;
    
    // Register commands
    _plugin_registercommand(pluginHandle, "testcmd", cb_test, false);
    _plugin_registercommand(pluginHandle, "timestamp", cb_timestamp, false);
    _plugin_registercommand(pluginHandle, "createcsv", cb_create_csv, false);
    _plugin_registercommand(pluginHandle, "closecsv", cb_close_csv, false);
    _plugin_registercommand(pluginHandle, "writetest", cb_write_test, false);
    
    // API commands for scripts
    _plugin_registercommand(pluginHandle, "gettimestamp", cb_get_timestamp, false);
    _plugin_registercommand(pluginHandle, "gettimemicros", cb_get_timestamp_micros, false);
    _plugin_registercommand(pluginHandle, "logentry", cb_log_entry, false);
    _plugin_registercommand(pluginHandle, "logmemvars", cb_logmem_vars, false);
    _plugin_registercommand(pluginHandle, "getsessionid", cb_get_session_id, false);
    _plugin_registercommand(pluginHandle, "csvstatus", cb_csv_status, false);
    
    // Automatically create CSV file on initialization
    createCSVFile();
    
    _plugin_logprintf("[%s] Plugin initialized\n", PLUGIN_NAME);
    _plugin_logprintf("[%s] Available commands:\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   testcmd - Test the plugin\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   timestamp [label] - Log current timestamp with microsecond precision\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   createcsv - Create/open CSV file\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   closecsv - Close CSV file and increment session ID\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   writetest - Write a test entry to CSV\n", PLUGIN_NAME);
    _plugin_logprintf("[%s] API for scripts:\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   gettimestamp - Get timestamp string in log\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   gettimemicros - Get timestamp as microseconds in $result\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   logentry label,hex_bytes[,timestamp] - Log entry to CSV\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   logmemvars label_var,addr_var,size_var[,time_var] - Log memory using variables\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   getsessionid - Get current session ID in $result\n", PLUGIN_NAME);
    _plugin_logprintf("[%s]   csvstatus - Show CSV file status\n", PLUGIN_NAME);
    return true;
}

// Plugin cleanup
bool pluginStop()
{
    // Close CSV file if open
    if (csvFileOpen)
    {
        closeCSVFile();
    }
    
    _plugin_logprintf("[%s] Plugin stopped\n", PLUGIN_NAME);
    return true;
}

// Plugin setup (GUI)
void pluginSetup()
{
    // Nothing for now
}

// Required DLL exports
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) bool plugstop()
{
    return pluginStop();
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    if (setupStruct)
    {
        hwndDlg = setupStruct->hwndDlg;
        hMenu = setupStruct->hMenu;
        hMenuDisasm = setupStruct->hMenuDisasm;
        hMenuDump = setupStruct->hMenuDump;
        hMenuStack = setupStruct->hMenuStack;
        hMenuGraph = setupStruct->hMenuGraph;
        hMenuMemmap = setupStruct->hMenuMemmap;
        hMenuSymmod = setupStruct->hMenuSymmod;
    }
    
    pluginSetup();
}
