# 📊 LogToCSV Plugin

[![License](https://img.shields.io/badge/license-BSL-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![x64dbg](https://img.shields.io/badge/x64dbg-plugin-green.svg)]()

> 🕒 High-precision timestamp logging plugin for x64dbg with microsecond accuracy and CSV export functionality.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| ⏱️ **Microsecond Precision** | Uses `GetSystemTimePreciseAsFileTime()` for sub-millisecond accuracy |
| 📈 **CSV Logging** | Structured data export with session tracking |
| 🔧 **Script API** | Full integration with x64dbg scripts for automated logging |
| 🗂️ **Session Management** | Automatic ID tracking across debugging sessions |
| 🔢 **Hex Formatting** | Automatic formatting of binary data for readability |
| 🧠 **Variable Support** | Direct evaluation of x64dbg variables and expressions |


## 🚀 Installation

### Quick Start

1. **Build the plugin:**
   ```bash
   cmake -B build64 -A x64
   cmake --build build64 --config Release
   ```

2. **Install the plugin:**
   ```bash
   # Copy to x64dbg plugins directory
   copy build64\Release\LogToCSV.dp64 "C:\x64dbg\plugins\"
   ```

3. **Restart x64dbg** and you're ready to go! 🎉

## 📋 CSV Output Format

The plugin creates `timing_13.csv` in your temp directory with the following structure:

```csv
ID,timestamp,label,secret
1,"2025-09-05 14:30:25.123456","function_start","48 89 4C 24 08"
1,"2025-09-05 14:30:25.789012","breakpoint_hit","E8 12 34 56 AB"
2,"2025-09-05 14:31:10.456789","new_session","CA FE BA BE"
```

### 📊 Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| **ID** | `Integer` | Session identifier (increments when CSV is closed/reopened) |
| **timestamp** | `String` | Microsecond-precision timestamp (`YYYY-MM-DD HH:MM:SS.mmmmmm`) |
| **label** | `String` | User-defined label for the event |
| **secret** | `String` | Hex bytes or custom data (automatically formatted) |

## 🎮 Commands

### 🔧 Basic Commands

| Command | Description | Example |
|---------|-------------|---------|
| `testcmd` | 🧪 Test plugin functionality | `testcmd` |
| `timestamp [label]` | ⏰ Display current timestamp | `timestamp "checkpoint"` |
| `createcsv` | 📂 Open/create CSV file | `createcsv` |
| `closecsv` | 🔒 Close CSV file and increment session ID | `closecsv` |
| `csvstatus` | 📊 Show CSV file status and session info | `csvstatus` |

### 🔌 Script API Commands

| Command | Description | Returns | Example |
|---------|-------------|---------|---------|
| `gettimestamp` | 📅 Get formatted timestamp | Log output | `gettimestamp` |
| `gettimemicros` | ⏱️ Get microseconds since epoch | `$result` | `gettimemicros` |
| `getsessionid` | 🔢 Get current session ID | `$result` | `getsessionid` |
| `logentry` | 📝 Log entry to CSV | Success/failure | `logentry start_func,48894C2408` |
| `logmemvars` | 🧠 Log memory using variables | Success/failure | `logmemvars label_addr,data_addr,size,timestamp` |

### 📋 Logging APIs

#### Basic Logging API
**Syntax:** `logentry label,hex_bytes[,custom_timestamp]`

**Examples:**
```bash
logentry function_start,48894C2408
logentry breakpoint_hit,CAFEBABE
logentry custom_event,DEADBEEF,2025-01-01 12:00:00.000000
```

#### 🆕 Advanced Memory Logging API
**Syntax:** `logmemvars label_var,address_var,size_var[,timestamp_var]`

> **💡 Recommended for scripts:** This command properly evaluates x64dbg variables and expressions, solving common parsing issues with the basic `logentry` command.

**Examples:**
```bash
# Log memory using variables
logmemvars saved_secret_kind,secret_ptr,secret_size,time_stamp

# Log with expressions
logmemvars rip,rsp,10,time_variable

# Log without custom timestamp (uses current time)
logmemvars my_label,data_address,data_size
```

**Advantages over `logentry`:**
- ✅ Properly evaluates x64dbg variables and expressions
- ✅ Reads memory directly from debugged process
- ✅ Handles complex expressions like `{mem;size@addr}`
- ✅ Automatic hex formatting with proper spacing
- ✅ No string parsing limitations

## 💻 Usage in x64dbg Scripts

### 📊 Basic Logging
```javascript
// Log function entry with basic command
logentry function_entry,{hex:eip,8}

// Get timestamp for calculations
gettimemicros
mov eax, $result
```

### 🧠 Advanced Memory Logging
```javascript
// Store data locations in variables
label_addr = saved_secret_kind    // Pointer to label string
data_addr = secret_ptr           // Pointer to actual data
data_size = secret_size          // Size of data to read

// Get precise timestamp
gettimemicros
timestamp_var = $result

// Log using variables (recommended approach)
logmemvars label_addr,data_addr,data_size,timestamp_var

// Alternative: Log without custom timestamp
logmemvars label_addr,data_addr,data_size
```

### ⚡ Performance Measurement
```javascript
// Start timing
gettimemicros
mov start_time, $result

// ... code being measured ...

// End timing
gettimemicros
sub $result, start_time
logentry execution_time,$result
```

### 🗂️ Session Management
```javascript
// Check current session
getsessionid
cmp $result, 1
je first_session

// Start new session
closecsv
createcsv
```

### 🔄 Migration from `logentry` to `logmemvars`

**Old problematic approach:**
```javascript
// ❌ This often fails due to expression parsing issues
logentry saved_secret_kind, "{mem;secret_size@secret_ptr}", time_stamp
```

**New recommended approach:**
```javascript
// ✅ This works reliably with proper variable evaluation
logmemvars saved_secret_kind,secret_ptr,secret_size,time_stamp
```

### 🚀 Quick Start Example

Here's a complete example showing how to use the new `logmemvars` feature:

```javascript
// 1. Ensure CSV is open
createcsv

// 2. Set up your data
my_label = "ssl_secret"      // Label for this entry
data_ptr = 0x401000         // Address of data to log
data_size = 32              // Size in bytes

// 3. Get precise timestamp
gettimemicros
my_time = $result

// 4. Log the memory content
logmemvars my_label,data_ptr,data_size,my_time

// 5. Check the results
csvstatus
```

This will create an entry in `%TEMP%\timing_13.csv` with properly formatted hex data and microsecond-precision timestamps.

## 📁 File Management

| Feature | Description |
|---------|-------------|
| 🚀 **Auto-creation** | CSV file is automatically created when plugin loads |
| 📝 **Append mode** | Existing files are opened in append mode (no data loss) |
| 🔄 **Session tracking** | Each close/reopen cycle increments the session ID |
| 📂 **Location** | Files are stored in the system temp directory (`%TEMP%\timing_13.csv`) |

## 🔧 Technical Details

### ⏰ Timestamp Precision
- Uses Windows `GetSystemTimePreciseAsFileTime()` API
- Provides 100-nanosecond resolution (limited to microseconds for readability)
- Local time zone conversion applied automatically

### 🛡️ Memory Safety
- All string operations use safe functions (`sprintf_s`, `strcpy_s`)
- Null pointer checks on all arguments
- Exception handling for file operations
- Memory bounds checking for variable-size data reads

### 🧠 Variable Expression Handling
- Uses x64dbg's `DbgEval()` for proper variable evaluation
- Supports complex expressions and memory references
- Direct memory reading from debugged process using `DbgMemRead()`
- Automatic conversion of binary data to readable hex format

### 📊 CSV Format Compliance
- Proper escaping of fields containing commas
- Quoted string fields for safety
- Standard CSV headers for easy import into analysis tools

---

## 🛠️ Development

This plugin is built using [cmkr](https://cmkr.build) with the configuration in `cmake.toml`.

### 🔨 Building

From a Visual Studio command prompt:

```bash
# 64-bit build (recommended)
cmake -B build64 -A x64
cmake --build build64 --config Release
```

The output will be `build64\LogToCSV.dp64` ready for installation.

To build a 32-bit plugin:

```bash
# 32-bit build
cmake -B build32 -A Win32
cmake --build build32 --config Release
```

### 📁 Project Structure

```
logToCSV/
├── 📄 src/
│   ├── pluginmain.cpp    # Main plugin implementation
│   └── pluginmain.h      # x64dbg plugin SDK headers
├── ⚙️ cmake.toml          # CMake configuration
├── 🔧 CMakeLists.txt      # Generated CMake file
└── 📊 timing_13.csv       # Output file (created in temp directory)
```

---

## 📚 References

| Resource | Description |
|----------|-------------|
| 📖 [x64dbg Plugin Development Guide](https://help.x64dbg.com/en/latest/developers/plugins/index.html) | Official plugin development documentation |
| 🔧 [x64dbg Plugin SDK](https://github.com/x64dbg/x64dbg/tree/development/src/bridge) | Source code and headers |
| 🎯 [Plugin Examples](https://plugins.x64dbg.com) | Community plugin gallery |

---
