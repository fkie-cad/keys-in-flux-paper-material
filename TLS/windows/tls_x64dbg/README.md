# TLS Secret Tracking for Windows 11 using x64dbg

## Structure

**script.txt**
A debugging script that tracks TLS secrets from the Windows LSASS process using x64dbg. This tool intercepts the `derive_secret` function in the `ncryptsslp` module to capture and log TLS handshake secrets, enabling TLS secret material availability analysis.

**tls12_script.txt**
A version of the debug script tracing TLS 1.2 Master Secrets.

**script_ps.txt**
A script that creates timed memory snapshots of the LSASS process at the events of KeyUpdate and Shutdown. This should be attached to the process initating the TLS connection.


## 📋 Prerequisites

### Required Software
- **x64dbg**: Windows x64 debugger ([Download](https://x64dbg.com/))
- **Administrative Privileges**: Required to attach to LSASS process
- **Windows 11**: Target system with TLS 1.3 support

### Required Plugin
- **LogToCSV Plugin**: Custom x64dbg plugin for CSV export
- **dump_lsass Plugin**: Custom x64dbg plugin for dumping process memory of lsass.exe

The plugins can be found in [../plugins](../plugins)

## 🚀 Installation & Setup

### 1. Install x64dbg Plugin

```bash
# Copy the plugin to your x64dbg plugins directory
copy LogToCSV.dp64 "C:\Path_To_x64dbg\release\x64\plugins\"
copy Dump_lsass.dp64 "C:\Path_To_x64dbg\release\x64\plugins\"
copy LsassDumpSyscall.exe "C:\Path_To_x64dbg\release\x64\plugins\"
```

### 2. Usage

If the automated batch file doesn't work completely:

1. **Launch x64dbg as Administrator**
2. **Attach to process (lsass.exe for logs / other process for dumps)**
3. **Load script**
4. **Execute scritpt**
5. **Establish TLS connection**

### Troubleshooting
If you encounter errors attaching to LSASS, you may need to temporarily disable process protection:

**Disable LSASS Protection (Windows 11):**
1. Open Windows Security → Device Security → Core Isolation.
2. Turn off "Memory Integrity" and restart your computer.
3. Try attaching to LSASS again.

**Warning:** Disabling protection reduces system security. Re-enable after debugging.

### Registry Modification

In some cases, you may need to disable LSASS protection via the Windows Registry:

**Disable LSASS Protection (Registry):**
1. Open `regedit.exe` as Administrator.
2. Navigate to:  
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
    ```
3. Set the value of `RunAsPPL` to `0`.
4. Restart your computer.

### Windwos Defender Protection

Windows Defender Realtime Protection must be disabled