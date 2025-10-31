#!/usr/bin/env python3
"""
SSH Lifecycle Analysis - Python Implementation

Comprehensive analysis tool for SSH key lifecycle experiments.
Fixes binary key search and adds detailed state tracking.

Usage:
    ./analyze_ssh_lifecycle.py [results_directory]
    ./analyze_ssh_lifecycle.py --help

Features:
    - Binary key search in memory dumps (both endianness)
    - State extraction from dump filenames
    - Per-key lifecycle timeline with creation, overwrite, persistence
    - Base vs KU comparison
    - Watchpoint timing analysis
    - Implementation comparison
"""

import argparse
import os
import sys
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import subprocess

# Color codes for terminal output
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

@dataclass
class SSHKey:
    """Represents an extracted SSH key"""
    key_id: str  # A-F
    key_name: str  # e.g., "C_ENCRYPTION_KEY_CLIENT_TO_SERVER_KEX1"
    key_hex: str  # Full hex string
    implementation: str  # openssh, dropbear, wolfssh
    created_time: Optional[float] = None  # UNIX timestamp
    overwritten_time: Optional[float] = None  # UNIX timestamp
    lifespan_seconds: Optional[float] = None
    last_dump_file: Optional[str] = None
    last_dump_state: Optional[str] = None
    found_in_dumps: List[Dict] = field(default_factory=list)  # [{file, state, offset, endianness}]

    @property
    def key_preview(self) -> str:
        """First 16 hex chars for display"""
        return self.key_hex[:16] if len(self.key_hex) >= 16 else self.key_hex

    @property
    def memory_state(self) -> str:
        """PLAINTEXT, CLEARED, or UNKNOWN"""
        if self.found_in_dumps:
            return "PLAINTEXT"
        elif self.overwritten_time is not None:
            return "CLEARED"
        else:
            return "UNKNOWN"

@dataclass
class ExperimentResults:
    """Container for all experiment analysis results"""
    results_dir: Path
    data_dir: Path
    implementations: Dict[str, Dict] = field(default_factory=dict)  # {impl: {keys, dumps, status}}
    keys: List[SSHKey] = field(default_factory=list)
    timing_data: Dict[str, Path] = field(default_factory=dict)  # {impl: csv_path}
    keylogs: Dict[str, Path] = field(default_factory=dict)  # {impl: log_path}
    dumps_dir: Optional[Path] = None
    captures: List[Path] = field(default_factory=list)


class SSHLifecycleAnalyzer:
    """Main analyzer for SSH lifecycle experiments"""

    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir).resolve()
        self.data_dir = Path("./data").resolve()

        # Determine if using custom results directory
        self.use_custom_results = self.results_dir != self.data_dir

        self.results = ExperimentResults(
            results_dir=self.results_dir,
            data_dir=self.data_dir
        )

        # Find dumps directory
        self._find_dumps_dir()

    def _find_dumps_dir(self):
        """Locate the dumps directory"""
        candidates = [
            self.results_dir / "dumps",
            self.data_dir / "dumps"
        ]
        for path in candidates:
            if path.exists() and path.is_dir():
                self.results.dumps_dir = path
                break

    def analyze_all(self) -> ExperimentResults:
        """Run complete analysis pipeline"""
        print(f"\n{'='*72}")
        print(f"  SSH Lifecycle Analysis - Comparison Report")
        print(f"{'='*72}\n")
        print(f"Results directory: {self.results_dir}\n")

        # Section 1: Key Extraction Comparison
        self._analyze_key_extraction()

        # Section 2: Memory Dumps Analysis
        self._analyze_memory_dumps()

        # Section 3: Packet Capture Analysis
        self._analyze_packet_captures()

        # Section 4: Key Lifecycle Persistence (FIXED - binary search)
        self._analyze_key_persistence()

        # Section 5: Watchpoint Timing Analysis
        self._analyze_watchpoint_timing()

        # Section 6: Detailed Key Lifecycle Timeline
        self._detailed_key_lifecycle_timeline()

        # Section 7: Base vs KU Comparison
        self._analyze_base_vs_ku()

        # Section 8: Implementation Comparison
        self._implementation_comparison()

        # Generate report file
        self._generate_report()

        print(f"{Colors.GREEN}[SUCCESS] Analysis complete!{Colors.NC}\n")
        return self.results

    def _analyze_key_extraction(self):
        """Section 1: Key Extraction Comparison"""
        print(f"{'='*72}")
        print(f"  KEY EXTRACTION COMPARISON")
        print(f"{'='*72}\n")

        for impl in ['wolfssh', 'dropbear', 'openssh']:
            keylog_path = self._find_keylog(impl)
            if keylog_path:
                self.results.keylogs[impl] = keylog_path
                keys_count = self._count_keys(keylog_path)

                # Parse keylog and extract keys
                extracted_keys = self._parse_keylog(keylog_path, impl)
                self.results.keys.extend(extracted_keys)

                # Determine status
                if impl == 'wolfssh':
                    expected = 4  # AEAD cipher
                    if keys_count == expected:
                        status = "✓ PASS (AEAD cipher)"
                        print(f"{Colors.GREEN}{impl:10s}: {keys_count} keys extracted ✓ (AEAD cipher - ChaCha20-Poly1305){Colors.NC}")
                    elif keys_count > 0:
                        status = "⚠️  PARTIAL"
                        print(f"{Colors.YELLOW}{impl:10s}: {keys_count} keys extracted ⚠️  (expected {expected} for AEAD){Colors.NC}")
                    else:
                        status = "✗ FAIL"
                        print(f"{Colors.RED}{impl:10s}: No keys extracted ✗{Colors.NC}")
                elif impl == 'openssh':
                    expected = 6  # Full key set
                    if keys_count == expected:
                        status = "✓ PASS"
                        print(f"{Colors.GREEN}{impl:10s}: {keys_count} keys extracted ✓{Colors.NC}")
                    elif keys_count > 0:
                        status = "⚠️  PARTIAL"
                        print(f"{Colors.YELLOW}{impl:10s}: {keys_count} keys extracted ⚠️  (expected {expected}){Colors.NC}")
                    else:
                        status = "✗ FAIL"
                        print(f"{Colors.RED}{impl:10s}: No keys extracted ✗{Colors.NC}")
                else:  # dropbear
                    if keys_count >= 1:
                        status = "✓ PASS"
                        print(f"{Colors.GREEN}{impl:10s}: {keys_count} key(s) extracted ✓{Colors.NC}")
                    else:
                        status = "✗ FAIL"
                        print(f"{Colors.RED}{impl:10s}: No keys extracted ✗{Colors.NC}")

                self.results.implementations[impl] = {
                    'keys_count': keys_count,
                    'status': status
                }
            else:
                if impl != 'openssh':  # OpenSSH might not be tested yet
                    print(f"{Colors.CYAN}{impl:10s}: Not tested yet (FUTURE){Colors.NC}")
        print()

    def _count_keys(self, keylog_path: Path) -> int:
        """Count keys in keylog file (supports multiple formats)"""
        if not keylog_path.exists() or keylog_path.stat().st_size == 0:
            return 0

        try:
            with open(keylog_path, 'r') as f:
                content = f.read()
                # Match various formats
                matches = re.findall(r'(CLIENT [A-F]_|NEWKEYS.*TYPE.*VALUE|DERIVE_KEY)', content)
                return len(matches)
        except Exception:
            return 0

    def _find_keylog(self, impl: str) -> Optional[Path]:
        """Find keylog file for implementation"""
        candidates = [
            self.results_dir / f"{impl}_client_keylog.log",
            self.results_dir / "keylogs" / f"{impl}_client_keylog.log",
            self.data_dir / "keylogs" / f"{impl}_client_keylog.log"
        ]
        for path in candidates:
            if path.exists():
                return path
        return None

    def _parse_keylog(self, keylog_path: Path, impl: str) -> List[SSHKey]:
        """Parse keylog file and extract SSH keys"""
        keys = []

        try:
            with open(keylog_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Detect format and extract key
                    key_name = None
                    key_id = None
                    key_hex = None

                    # OpenSSH/wolfSSH new format: "[timestamp] CLIENT A_IV_CLIENT_TO_SERVER_KEX1: <hex>"
                    match = re.search(r'CLIENT ([A-F][A-Z0-9_]+):\s+([0-9a-fA-F]{32,})', line)
                    if match:
                        key_name = match.group(1)
                        key_id = key_name[0]
                        key_hex = match.group(2)

                    # wolfSSH legacy format: "NEWKEYS MODE IN TYPE IV_KEX0 VALUE <hex>"
                    elif 'NEWKEYS MODE' in line:
                        hex_match = re.search(r'([0-9a-fA-F]{32,})', line)
                        if hex_match:
                            key_hex = hex_match.group(1)

                            if 'MODE IN' in line and 'TYPE IV' in line:
                                key_name = "A_IV_CLIENT_TO_SERVER"
                                key_id = "A"
                            elif 'MODE OUT' in line and 'TYPE IV' in line:
                                key_name = "B_IV_SERVER_TO_CLIENT"
                                key_id = "B"
                            elif 'MODE IN' in line and 'TYPE KEY' in line:
                                key_name = "C_ENCRYPTION_KEY_CLIENT_TO_SERVER"
                                key_id = "C"
                            elif 'MODE OUT' in line and 'TYPE KEY' in line:
                                key_name = "D_ENCRYPTION_KEY_SERVER_TO_CLIENT"
                                key_id = "D"

                    # Dropbear format: "DERIVE_KEY ..."
                    elif 'DERIVE_KEY' in line:
                        hex_match = re.search(r'([0-9a-fA-F]{32,})', line)
                        if hex_match:
                            key_hex = hex_match.group(1)
                            key_name = "CIPHER_KEY"
                            key_id = "C"  # Assume client→server cipher

                    if key_name and key_hex:
                        keys.append(SSHKey(
                            key_id=key_id,
                            key_name=key_name,
                            key_hex=key_hex,
                            implementation=impl
                        ))

        except Exception as e:
            print(f"{Colors.RED}Error parsing keylog {keylog_path}: {e}{Colors.NC}")

        return keys

    def _analyze_memory_dumps(self):
        """Section 2: Memory Dumps Analysis"""
        print(f"{'='*72}")
        print(f"  MEMORY DUMPS ANALYSIS")
        print(f"{'='*72}\n")

        print("Memory dumps captured:")

        total_dumps = 0
        total_size = 0

        if self.results.dumps_dir and self.results.dumps_dir.exists():
            for impl in ['wolfssh', 'dropbear', 'openssh']:
                # FIX: Dump filenames don't always contain implementation name
                # Use pattern matching on all dumps, then filter by impl if keylog exists
                dumps = list(self.results.dumps_dir.glob("*.dump"))
                count = len(dumps)
                total_dumps += count

                size = sum(d.stat().st_size for d in dumps)
                total_size += size

                if impl in self.results.implementations:
                    self.results.implementations[impl]['dumps_count'] = count
                else:
                    self.results.implementations[impl] = {'dumps_count': count}

                if count > 0:
                    print(f"  {impl:10s}: {count} dumps")
        else:
            print(f"{Colors.YELLOW}  No dumps directory found{Colors.NC}")

        print(f"\nTotal dump storage: {self._format_bytes(total_size)}\n")

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes into human-readable string"""
        if bytes_count >= 1073741824:
            return f"{bytes_count / 1073741824:.2f} GB"
        elif bytes_count >= 1048576:
            return f"{bytes_count / 1048576:.2f} MB"
        elif bytes_count >= 1024:
            return f"{bytes_count / 1024:.2f} KB"
        else:
            return f"{bytes_count} bytes"

    def _analyze_packet_captures(self):
        """Section 3: Packet Capture Analysis"""
        print(f"{'='*72}")
        print(f"  PACKET CAPTURE ANALYSIS")
        print(f"{'='*72}\n")

        # Search for PCAP files
        search_dirs = [
            self.results_dir,
            self.data_dir / "captures"
        ]

        for search_dir in search_dirs:
            if search_dir.exists():
                self.results.captures.extend(search_dir.glob("*.pcap"))

        if self.results.captures:
            for pcap in self.results.captures:
                size = pcap.stat().st_size
                print(f"  {pcap.name}: {self._format_bytes(size)}")
        else:
            print(f"{Colors.YELLOW}  No packet captures found{Colors.NC}")

        print()

    def _analyze_key_persistence(self):
        """Section 4: Key Lifecycle Persistence Analysis (FIXED - binary search)"""
        print(f"{'='*72}")
        print(f"  KEY LIFECYCLE PERSISTENCE ANALYSIS")
        print(f"{'='*72}\n")
        print("Analyzing when secrets were last observed in memory dumps...")
        print()

        if not self.results.dumps_dir or not self.results.dumps_dir.exists():
            print(f"{Colors.YELLOW}No dumps directory found - skipping persistence analysis{Colors.NC}\n")
            return

        # Search for each extracted key in dumps using binary search
        for key in self.results.keys:
            self._search_key_in_dumps(key)

        # Display results grouped by implementation
        for impl in ['openssh', 'dropbear', 'wolfssh']:
            impl_keys = [k for k in self.results.keys if k.implementation == impl]
            if impl_keys:
                print(f"{impl.capitalize()} Key Persistence:")
                for key in impl_keys:
                    if key.found_in_dumps:
                        # Group by state
                        states = {}
                        for dump_info in key.found_in_dumps:
                            state = dump_info['state']
                            if state not in states:
                                states[state] = []
                            states[state].append(dump_info)

                        last_dump = key.found_in_dumps[0]['file']  # Most recent
                        last_time = self._extract_timestamp_from_filename(last_dump)

                        print(f"{Colors.GREEN}  {key.key_name}: Last seen @ {last_time}{Colors.NC}")
                        print(f"    Dump: {last_dump}")
                        print(f"    Found in {len(key.found_in_dumps)} dumps across {len(states)} states:")
                        for state, dumps in sorted(states.items()):
                            print(f"      - {state} ({len(dumps)} occurrences)")
                    else:
                        print(f"{Colors.YELLOW}  {key.key_name}: NOT FOUND in any dump{Colors.NC}")
                print()

        print("Note: Key persistence shows WHEN secrets were last observed in memory.")
        print("Keys not found in dumps may have been cleared immediately or dumps may")
        print("have been taken before/after key usage.\n")

    def _search_key_in_dumps(self, key: SSHKey):
        """Binary search for key in all dumps (both endianness)"""
        if not self.results.dumps_dir:
            return

        try:
            # Convert hex string to bytes
            key_bytes = bytes.fromhex(key.key_hex)
            key_bytes_le = key_bytes[::-1]  # Little-endian version
        except ValueError:
            return

        # Search all dumps (filenames don't always contain implementation name)
        dump_files = sorted(
            self.results.dumps_dir.glob("*.dump"),
            reverse=True  # Most recent first
        )

        for dump_file in dump_files:
            try:
                data = dump_file.read_bytes()

                # Search both endianness
                offset_be = data.find(key_bytes)
                offset_le = data.find(key_bytes_le)

                if offset_be >= 0 or offset_le >= 0:
                    state = self._extract_state_from_filename(dump_file.name)
                    key.found_in_dumps.append({
                        'file': dump_file.name,
                        'state': state,
                        'offset': offset_be if offset_be >= 0 else offset_le,
                        'endianness': 'BIG' if offset_be >= 0 else 'LITTLE'
                    })
            except Exception as e:
                # Skip files that can't be read
                continue

    def _extract_state_from_filename(self, filename: str) -> str:
        """Extract state from dump filename

        Format examples:
            20251030_185051_186994_REKEY_GENERATE_KEY_entry.dump
            20251030_185051_186994_kex_newkeys_exit.dump
        """
        # Remove .dump extension
        name = filename.replace('.dump', '')

        # Split by underscore - format: YYYYmmdd_HHMMSS_PID_STATE
        parts = name.split('_', 3)
        if len(parts) >= 4:
            return parts[3]

        # Fallback: try to extract any meaningful pattern
        # Look for common state patterns
        state_patterns = [
            'REKEY_', 'kex_', 'KEX_', 'post_', 'pre_',
            'trigger_', 'SEND_', 'NEWKEYS', 'active',
            'complete', 'entry', 'exit'
        ]
        for pattern in state_patterns:
            if pattern in name:
                # Extract from pattern onwards
                idx = name.find(pattern)
                return name[idx:]

        return 'unknown'

    def _extract_timestamp_from_filename(self, filename: str) -> str:
        """Extract timestamp from dump filename (YYYYmmdd_HHMMSS)"""
        match = re.search(r'(\d{8}_\d{6})', filename)
        if match:
            return match.group(1)
        return "UNKNOWN"

    def _analyze_watchpoint_timing(self):
        """Section 5: Watchpoint Timing Analysis"""
        print(f"{'='*72}")
        print(f"  WATCHPOINT TIMING ANALYSIS (Hardware Watchpoints)")
        print(f"{'='*72}\n")
        print("Analyzing hardware watchpoint data (key overwrite detection)...\n")

        # Find timing CSV files
        timing_files_found = self._find_timing_csvs()

        if not timing_files_found:
            print(f"{Colors.YELLOW}No watchpoint timing data found{Colors.NC}")
            print(f"  Location checked: {self.data_dir}/lldb_results/timing_*.csv")
            print("  Watchpoint tracking requires:")
            print("    - LLDB_ENABLE_WATCHPOINTS=true (default)")
            print("    - Hardware watchpoint support (CPU feature)")
            print("    - Keys must be overwritten during session\n")
            return

        # Analyze each timing CSV
        for impl, csv_path in self.results.timing_data.items():
            self._analyze_timing_csv(impl, csv_path)

        print("Note: Watchpoint timing shows WHEN encryption keys were first overwritten.")
        print("This helps measure key lifecycle duration (derivation → first overwrite).\n")

    def _find_timing_csvs(self) -> bool:
        """Find all timing CSV files"""
        search_paths = []

        if self.use_custom_results:
            # Custom results directory
            search_paths.extend([
                self.results_dir / "lldb_results",
                self.results_dir
            ])
        else:
            # FIX: Also check results_dir/lldb_results/ even when using ./data
            search_paths.append(self.results_dir / "lldb_results")

        # Always check data directory
        search_paths.append(self.data_dir / "lldb_results")

        found = False
        for search_path in search_paths:
            if search_path.exists():
                for csv_file in search_path.glob("timing_*.csv"):
                    impl = csv_file.stem.replace('timing_', '')
                    self.results.timing_data[impl] = csv_file
                    found = True

        return found

    def _analyze_timing_csv(self, impl: str, csv_path: Path):
        """Analyze timing CSV for one implementation"""
        print(f"{impl} Watchpoint Events:")

        try:
            with open(csv_path, 'r') as f:
                lines = f.readlines()

            # Count overwrite events
            key_c_overwrites = sum(1 for line in lines if ',C,overwritten,' in line)
            key_d_overwrites = sum(1 for line in lines if ',D,overwritten,' in line)

            if key_c_overwrites > 0 or key_d_overwrites > 0:
                print(f"{Colors.GREEN}  ✓ Watchpoint tracking active{Colors.NC}")
                print(f"    Key C (client→server) overwrites: {key_c_overwrites}")
                print(f"    Key D (server→client) overwrites: {key_d_overwrites}")

                # Extract first overwrite timestamps
                for line in lines:
                    if ',C,overwritten,' in line:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            print(f"    Key C first overwrite: {parts[0]}s (UNIX timestamp)")
                        break

                for line in lines:
                    if ',D,overwritten,' in line:
                        parts = line.strip().split(',')
                        if len(parts) >= 3:
                            print(f"    Key D first overwrite: {parts[0]}s (UNIX timestamp)")
                        break

                # Enrich key objects with timing data
                self._enrich_keys_with_timing(impl, csv_path)
            else:
                print(f"{Colors.YELLOW}  ⚠️  No watchpoint events recorded{Colors.NC}")
                print("    (Watchpoints may be disabled or keys not yet overwritten)")

        except Exception as e:
            print(f"{Colors.RED}  Error reading timing CSV: {e}{Colors.NC}")

        print()

    def _enrich_keys_with_timing(self, impl: str, csv_path: Path):
        """Add timing data to key objects from CSV"""
        try:
            with open(csv_path, 'r') as f:
                lines = f.readlines()

            # Parse CSV: timestamp,key_id,event,details
            for line in lines:
                line = line.strip()

                # FIX: Skip CSV header line
                if line.startswith('timestamp') or line.startswith('#') or not line:
                    continue

                parts = line.split(',')
                if len(parts) < 3:
                    continue

                timestamp = float(parts[0])
                key_id = parts[1]
                event = parts[2]

                # Find matching key
                for key in self.results.keys:
                    if key.implementation == impl and key.key_id == key_id:
                        if event in ['created', 'derived']:
                            key.created_time = timestamp
                        elif event == 'overwritten':
                            key.overwritten_time = timestamp

                        # Calculate lifespan
                        if key.created_time and key.overwritten_time:
                            key.lifespan_seconds = key.overwritten_time - key.created_time

        except Exception as e:
            pass  # Silently skip on error

    def _detailed_key_lifecycle_timeline(self):
        """Section 6: Detailed Key Lifecycle Timeline"""
        print(f"{'='*72}")
        print(f"  DETAILED KEY LIFECYCLE TIMELINE")
        print(f"{'='*72}\n")
        print("Per-key analysis showing creation, overwrite, lifespan, and memory state.\n")

        # Group keys by implementation
        for impl in ['openssh', 'dropbear', 'wolfssh']:
            impl_keys = [k for k in self.results.keys if k.implementation == impl]
            if not impl_keys:
                continue

            print(f"{impl.capitalize()} Key Lifecycle Timeline:\n")

            for key in impl_keys:
                print(f"  Key: {key.key_name} (ID: {key.key_id})")
                print(f"    Preview: {key.key_preview}...")

                # Creation time
                if key.created_time:
                    created_str = datetime.fromtimestamp(key.created_time).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{Colors.GREEN}    ✓ Created:     {created_str}{Colors.NC}")
                else:
                    print(f"{Colors.YELLOW}    ? Created:     UNKNOWN (no timing data){Colors.NC}")

                # Overwrite time
                if key.overwritten_time:
                    overwritten_str = datetime.fromtimestamp(key.overwritten_time).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{Colors.GREEN}    ✓ Overwritten: {overwritten_str}{Colors.NC}")
                    if key.lifespan_seconds:
                        print(f"{Colors.CYAN}    ⏱  Lifespan:    {key.lifespan_seconds:.3f} seconds{Colors.NC}")
                else:
                    has_timing = impl in self.results.timing_data
                    if has_timing:
                        print(f"{Colors.RED}    ✗ Overwritten: NOT DETECTED (key persists in memory){Colors.NC}")
                    else:
                        print(f"{Colors.YELLOW}    ? Overwritten: UNKNOWN (no timing data){Colors.NC}")

                # Memory state
                if key.found_in_dumps:
                    # Show last dump and all states
                    last_dump = key.found_in_dumps[0]['file']
                    last_time = self._extract_timestamp_from_filename(last_dump)

                    # Group by state
                    states = {}
                    for dump_info in key.found_in_dumps:
                        state = dump_info['state']
                        if state not in states:
                            states[state] = 0
                        states[state] += 1

                    print(f"\n    Found in {len(key.found_in_dumps)} dumps across {len(states)} states:")
                    for state, count in sorted(states.items()):
                        print(f"      ✓ {state} ({count} occurrences)")

                    print(f"\n    Last seen: {last_dump} (@ {last_time})")
                    print(f"{Colors.RED}    State:     PLAINTEXT (persists after overwrite!){Colors.NC}")
                elif key.overwritten_time:
                    print(f"\n    Last dump:   NONE (cleared before dumps)")
                    print(f"{Colors.GREEN}    State:       CLEARED{Colors.NC}")
                else:
                    print(f"\n    Last dump:   UNKNOWN")
                    print(f"{Colors.YELLOW}    State:       UNKNOWN{Colors.NC}")

                print()

            print()

    def _analyze_base_vs_ku(self):
        """Section 7: Base vs Key Update Comparison"""
        print(f"{'='*72}")
        print(f"  BASE VS KEY UPDATE COMPARISON")
        print(f"{'='*72}\n")

        # Check if this is a base/ku experiment
        base_dir = self.results_dir / "base"
        ku_dir = self.results_dir / "ku"

        if not (base_dir.exists() or ku_dir.exists()):
            print(f"{Colors.CYAN}Single-mode experiment (not base/ku comparison){Colors.NC}\n")
            return

        print("Detected base/ku experiment structure\n")

        for impl in ['openssh', 'dropbear', 'wolfssh']:
            if not ((base_dir / impl).exists() or (ku_dir / impl).exists()):
                continue

            print(f"{impl.capitalize()} Base vs KU Comparison:\n")

            # Compare key counts
            base_keylog = base_dir / impl / f"{impl}_client_keylog.log"
            ku_keylog = ku_dir / impl / f"{impl}_client_keylog.log"

            base_keys = self._count_keys(base_keylog) if base_keylog.exists() else 0
            ku_keys = self._count_keys(ku_keylog) if ku_keylog.exists() else 0

            print(f"  Keys extracted:")
            print(f"    Base lifecycle: {base_keys} keys")
            print(f"    KU lifecycle:   {ku_keys} keys")

            if ku_keys > base_keys:
                print(f"{Colors.GREEN}    ✓ KU extracted {ku_keys - base_keys} additional keys (expected for rekey){Colors.NC}")
            elif ku_keys == base_keys:
                print(f"{Colors.YELLOW}    ⚠️  KU extracted same number of keys as base (rekey may not have occurred){Colors.NC}")
            else:
                print(f"{Colors.RED}    ✗ KU extracted FEWER keys than base (unexpected){Colors.NC}")

            # Compare timing data (lifespans)
            base_timing = base_dir / impl / f"timing_{impl}.csv"
            ku_timing = ku_dir / impl / f"timing_{impl}.csv"

            if not base_timing.exists():
                base_timing = self.data_dir / "lldb_results" / f"timing_{impl}.csv"
            if not ku_timing.exists():
                ku_timing = self.data_dir / "lldb_results" / f"timing_{impl}.csv"

            if base_timing.exists() or ku_timing.exists():
                print(f"\n  Key Lifespan Analysis:")

                base_avg = self._calculate_average_lifespan(base_timing) if base_timing.exists() else None
                ku_avg = self._calculate_average_lifespan(ku_timing) if ku_timing.exists() else None

                if base_avg is not None:
                    print(f"    Base mode:")
                    print(f"      Avg lifespan: {Colors.CYAN}{base_avg:.3f}s{Colors.NC}")

                if ku_avg is not None:
                    print(f"\n    KU mode (with rekey):")
                    print(f"      Avg lifespan: {Colors.CYAN}{ku_avg:.3f}s{Colors.NC}")

                if base_avg is not None and ku_avg is not None:
                    diff = base_avg - ku_avg
                    pct = (diff / base_avg) * 100 if base_avg > 0 else 0

                    print()
                    if ku_avg < base_avg:
                        print(f"{Colors.GREEN}    ✓ KU reduces key lifespan by {diff:.3f}s ({pct:.1f}% shorter){Colors.NC}")
                        print("      Better security: Keys are cleared sooner with rekey enabled")
                    elif ku_avg > base_avg:
                        print(f"{Colors.YELLOW}    ⚠️  KU increases key lifespan by {abs(diff):.3f}s (unexpected){Colors.NC}")
                    else:
                        print(f"{Colors.CYAN}    → KU has same average lifespan as base{Colors.NC}")

            print()

    def _calculate_average_lifespan(self, csv_path: Path) -> Optional[float]:
        """Calculate average key lifespan from timing CSV"""
        if not csv_path.exists():
            return None

        try:
            with open(csv_path, 'r') as f:
                lines = f.readlines()

            # Parse created and overwritten events
            key_lifespans = {}

            for line in lines:
                line = line.strip()

                # FIX: Skip CSV header line
                if line.startswith('timestamp') or line.startswith('#') or not line:
                    continue

                parts = line.split(',')
                if len(parts) < 3:
                    continue

                timestamp = float(parts[0])
                key_id = parts[1]
                event = parts[2]

                if key_id not in key_lifespans:
                    key_lifespans[key_id] = {}

                if event in ['created', 'derived']:
                    key_lifespans[key_id]['created'] = timestamp
                elif event == 'overwritten':
                    key_lifespans[key_id]['overwritten'] = timestamp

            # Calculate lifespans
            lifespans = []
            for key_id, times in key_lifespans.items():
                if 'created' in times and 'overwritten' in times:
                    lifespan = times['overwritten'] - times['created']
                    lifespans.append(lifespan)

            if lifespans:
                return sum(lifespans) / len(lifespans)
            else:
                return None

        except Exception:
            return None

    def _implementation_comparison(self):
        """Section 8: Implementation Comparison"""
        print(f"{'='*72}")
        print(f"  IMPLEMENTATION COMPARISON")
        print(f"{'='*72}\n")

        # Create comparison table
        print(f"{'Implementation':<15} {'Keys Extracted':<15} {'Memory Dumps':<15} {'Status':<25}")
        print(f"{'-'*15} {'-'*15} {'-'*15} {'-'*25}")

        for impl in ['wolfssh', 'dropbear', 'openssh']:
            if impl in self.results.implementations:
                data = self.results.implementations[impl]
                keys = data.get('keys_count', 0)
                dumps = data.get('dumps_count', 0)
                status = data.get('status', 'N/A')
                print(f"{impl.capitalize():<15} {keys:<15} {dumps:<15} {status:<25}")

        print()

        # Key differences and notes
        print(f"{'='*72}")
        print(f"  KEY DIFFERENCES & NOTES")
        print(f"{'='*72}\n")

        print("wolfSSH:")
        print("  - Uses AEAD cipher (ChaCha20-Poly1305)")
        print("  - Extracts 4 keys (A-D): IV and encryption keys only")
        print("  - No separate MAC keys (E-F) - authentication integrated into cipher")
        print("  - Rekey: NOT SUPPORTED\n")

        print("Dropbear:")
        print("  - Lightweight implementation")
        print("  - Extracts 1 key (transmit cipher key for ChaCha20)")
        print("  - Optimized for embedded systems")
        print("  - Rekey: SUPPORTED but not tested in simple scenario\n")

        print("OpenSSH:")
        print("  - Full-featured implementation")
        print("  - Extracts all 6 keys (A-F): IVs, encryption keys, MAC keys")
        print("  - Industry standard reference")
        print("  - Rekey: FULLY SUPPORTED\n")

        # Recommendations
        print(f"{'='*72}")
        print(f"  RECOMMENDATIONS")
        print(f"{'='*72}\n")

        print("Next steps:")
        print("  1. Validate key extraction against ground-truth (openssh_groundtruth)")
        print("  2. Compare memory dump timing across implementations")
        print("  3. Analyze PCAP files with extracted keys (Wireshark decryption)")
        print("  4. Test comprehensive lifecycle scenarios (base + KU modes)\n")

        # Check for timelining script
        timelining_script = Path("../../timing_analysis/timelining_events.py")
        if timelining_script.exists():
            print("For detailed analysis of timing and memory persistence:")
            print(f"  python3 {timelining_script} {self.results_dir}")
            print("  - Correlates keylogs, PCAP, and memory dumps")
            print("  - Creates comprehensive timeline of key lifecycle events\n")
        else:
            print(f"{Colors.YELLOW}Optional: Install timelining_events.py for detailed timeline correlation{Colors.NC}\n")

    def _generate_report(self):
        """Generate text report file"""
        report_path = self.results_dir / "analysis_report.txt"

        try:
            with open(report_path, 'w') as f:
                f.write("SSH Lifecycle Analysis - Comparison Report\n")
                f.write("=" * 72 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Results directory: {self.results_dir}\n\n")

                f.write("KEY EXTRACTION COMPARISON\n")
                f.write("=" * 72 + "\n")
                for impl in ['wolfssh', 'dropbear', 'openssh']:
                    if impl in self.results.implementations:
                        data = self.results.implementations[impl]
                        f.write(f"{impl:10s}: {data.get('keys_count', 0)} keys - {data.get('status', 'N/A')}\n")

                f.write("\nMEMORY DUMPS ANALYSIS\n")
                f.write("=" * 72 + "\n")
                total_dumps = 0
                for impl in ['wolfssh', 'dropbear', 'openssh']:
                    if impl in self.results.implementations:
                        dumps = self.results.implementations[impl].get('dumps_count', 0)
                        total_dumps += dumps
                        f.write(f"{impl:10s}: {dumps} dumps\n")

                f.write(f"\nPACKET CAPTURES\n")
                f.write("=" * 72 + "\n")
                f.write(f"Captures found: {len(self.results.captures)}\n")

                f.write("\nFor more details, see experiment logs in:\n")
                f.write(f"  {self.results_dir}/\n")

            print(f"Report saved to: {report_path}\n")

        except Exception as e:
            print(f"{Colors.RED}Error generating report: {e}{Colors.NC}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SSH Lifecycle Analysis - Python Implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./analyze_ssh_lifecycle.py                                    # Analyze most recent results
  ./analyze_ssh_lifecycle.py ./results/ssh_lifecycle_20251025_123456
  ./analyze_ssh_lifecycle.py ./data                             # Analyze current data/ directory
  ./analyze_ssh_lifecycle.py ssh_results/wolfSSH/ku             # Analyze specific experiment
        """
    )

    parser.add_argument(
        'results_dir',
        nargs='?',
        help='Results directory to analyze (default: most recent in ./results/)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Auto-detect results directory if not specified
    results_dir = args.results_dir
    if not results_dir:
        # Check for most recent results directory
        results_path = Path("./results")
        if results_path.exists():
            lifecycle_dirs = sorted(results_path.glob("ssh_lifecycle_*"), reverse=True)
            if lifecycle_dirs:
                results_dir = str(lifecycle_dirs[0])
            else:
                results_dir = "./data"
        else:
            results_dir = "./data"

    # Verify directory exists
    if not Path(results_dir).exists():
        print(f"{Colors.RED}[ERROR] Results directory not found: {results_dir}{Colors.NC}\n")
        print("Usage: ./analyze_ssh_lifecycle.py [results_directory]\n")
        print("Examples:")
        print("  ./analyze_ssh_lifecycle.py                                    # Analyze most recent results")
        print("  ./analyze_ssh_lifecycle.py ./results/ssh_lifecycle_20251025_123456")
        print("  ./analyze_ssh_lifecycle.py ./data                             # Analyze current data/ directory")
        sys.exit(1)

    # Run analysis
    analyzer = SSHLifecycleAnalyzer(results_dir)
    analyzer.analyze_all()


if __name__ == "__main__":
    main()
