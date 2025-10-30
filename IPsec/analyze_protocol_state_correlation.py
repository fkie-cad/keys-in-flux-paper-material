#!/usr/bin/env python3
"""
Protocol State Event Correlation Analyzer

Analyzes which IKEv2/IPsec protocol state transitions trigger cryptographic
key overwrites by correlating:
- Hardware watchpoint timing data (timing_*.csv)
- Memory dump checkpoints (dump_*.bin filenames)
- Protocol state transitions

This tool answers: "What protocol events cause keys to be overwritten?"

Usage:
    ./analyze_protocol_state_correlation.py \\
        libreswan/experiment/results/20251020_101402/userspace/left \\
        strongswan/experiment/results/20251013_135547/userspace/left
"""

import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import re


@dataclass
class ProtocolEvent:
    """Represents a protocol state transition"""
    timestamp: datetime
    state: str  # IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, REKEY, TERMINATE
    checkpoint_name: str  # Actual checkpoint/dump name
    implementation: str  # 'libreswan' or 'strongswan'


@dataclass
class KeyOverwrite:
    """Represents a key overwrite event from watchpoint"""
    timestamp: datetime
    key_name: str
    new_value: str
    is_cleared: bool  # True if overwritten with zeros


class ProtocolStateMapper:
    """Maps checkpoint names to IKEv2 protocol states"""

    # Mapping for strongSwan (already protocol-state based)
    STRONGSWAN_MAP = {
        'init': 'INIT',
        'before_handshake': 'IKE_SA_INIT_START',
        'after_handshake': 'IKE_AUTH_COMPLETE',
        'before_child_sa': 'CREATE_CHILD_SA_START',
        'after_child_sa': 'CREATE_CHILD_SA_COMPLETE',
        'before_rekey': 'REKEY_START',
        'after_rekey': 'REKEY_COMPLETE',
        'ike_state_terminate_entry': 'TERMINATE',
        'terminate_ike_entry': 'TERMINATE_COMPLETE',
    }

    # Mapping for LibreSwan (function-based, requires inference)
    LIBRESWAN_PATTERNS = [
        # IKE SA key material derivation = During IKE_SA_INIT/IKE_AUTH
        (r'ikev2_ike_sa_keymat_\d{3}_entry', 'IKE_SA_KEYMAT_START'),
        (r'ikev2_ike_sa_keymat_\d{3}_exit', 'IKE_SA_KEYMAT_COMPLETE'),

        # Child SA key material derivation = During CREATE_CHILD_SA
        (r'ikev2_child_sa_keymat_\d{3}_entry', 'CREATE_CHILD_SA_KEYMAT_START'),
        (r'ikev2_child_sa_keymat_\d{3}_exit', 'CREATE_CHILD_SA_KEYMAT_COMPLETE'),

        # Key extraction from PK11SymKey = Post-derivation processing
        (r'chunk_from_symkey_\d{3}_entry', 'KEY_EXTRACTION_START'),
        (r'chunk_from_symkey_\d{3}_exit', 'KEY_EXTRACTION_COMPLETE'),

        # Rekey operations
        (r'ike_sa_rekey_skeyseed.*', 'IKE_SA_REKEY'),

        # Cleanup operations = Post-handshake
        (r'cleanup_dh_shared_secret.*', 'DH_CLEANUP'),
        (r'iketcp_cleanup.*', 'TCP_CLEANUP'),

        # Termination
        (r'terminate_a_connection.*', 'TERMINATE_START'),
        (r'after_terminate.*', 'TERMINATE_COMPLETE'),
        (r'rekey_connection_now.*', 'REKEY_TRIGGER'),
        (r'rekey_now.*', 'REKEY_EXECUTE'),

        # Init
        (r'init.*', 'INIT'),
    ]

    @classmethod
    def map_checkpoint(cls, checkpoint_name: str, implementation: str) -> str:
        """Map checkpoint name to protocol state"""
        if implementation == 'strongswan':
            # Remove timestamp suffix
            clean_name = re.sub(r'_\d{8}_\d{6}(_\d+)?$', '', checkpoint_name)
            clean_name = re.sub(r'^dump_', '', clean_name)
            return cls.STRONGSWAN_MAP.get(clean_name, f'UNKNOWN_{clean_name}')

        elif implementation == 'libreswan':
            # Remove timestamp and prefixes
            clean_name = re.sub(r'_\d{8}_\d{6}(_\d+)?\.bin$', '', checkpoint_name)
            clean_name = re.sub(r'^dump_', '', clean_name)

            # Try pattern matching
            for pattern, state in cls.LIBRESWAN_PATTERNS:
                if re.match(pattern, clean_name):
                    return state

            return f'UNKNOWN_{clean_name}'

        return 'UNKNOWN'


class StateCorrelationAnalyzer:
    """Correlates key overwrites with protocol state transitions"""

    def __init__(self, results_dir: Path, implementation: str):
        self.results_dir = results_dir.absolute()  # Ensure absolute path
        self.implementation = implementation
        self.protocol_events: List[ProtocolEvent] = []
        self.key_overwrites: List[KeyOverwrite] = []

    def parse_dumps(self):
        """Parse memory dump filenames to extract protocol events"""
        dump_files = sorted(self.results_dir.glob('dump_*.bin'))

        for dump_file in dump_files:
            # Extract timestamp from filename
            match = re.search(r'_(\d{8})_(\d{6})_(\d+)\.bin$', dump_file.name)
            if not match:
                continue

            date_str, time_str, _ = match.groups()
            timestamp = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")

            checkpoint_name = dump_file.name.replace('dump_', '').replace('.bin', '')
            state = ProtocolStateMapper.map_checkpoint(checkpoint_name, self.implementation)

            self.protocol_events.append(ProtocolEvent(
                timestamp=timestamp,
                state=state,
                checkpoint_name=checkpoint_name,
                implementation=self.implementation
            ))

        # Sort by timestamp
        self.protocol_events.sort(key=lambda e: e.timestamp)

    def parse_timing_csv(self):
        """Parse timing CSV to extract key overwrite events"""
        # Auto-detect CSV file
        csv_path = self.results_dir / f"timing_{self.implementation}.csv"
        if not csv_path.exists():
            print(f"[!] Warning: No timing CSV found: {csv_path}")
            print(f"    (Current dir: {self.results_dir.absolute()})")
            return

        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip empty rows
                if not row.get('ID') or not row['ID'].strip():
                    continue

                event = row.get(' event', row.get('event', '')).strip()
                if not event.endswith('_overwritten'):
                    continue

                key_name = row.get(' key_name', row.get('key_name', '')).strip()
                timestamp_str = row.get(' timestamp', row.get('timestamp', '')).strip()
                value = row.get(' value', row.get('value', '')).strip()

                timestamp = datetime.fromisoformat(timestamp_str)
                is_cleared = set(value.replace('0', '')) == set()

                self.key_overwrites.append(KeyOverwrite(
                    timestamp=timestamp,
                    key_name=key_name,
                    new_value=value,
                    is_cleared=is_cleared
                ))

        # Sort by timestamp
        self.key_overwrites.sort(key=lambda k: k.timestamp)

    def correlate_overwrites_with_states(self) -> List[Tuple[KeyOverwrite, Optional[ProtocolEvent], Optional[ProtocolEvent]]]:
        """
        Correlate each key overwrite with nearest protocol events.

        Returns:
            List of (overwrite, preceding_event, following_event)
        """
        correlations = []

        for overwrite in self.key_overwrites:
            # Find preceding event (closest before overwrite)
            preceding = None
            for event in reversed(self.protocol_events):
                if event.timestamp <= overwrite.timestamp:
                    preceding = event
                    break

            # Find following event (closest after overwrite)
            following = None
            for event in self.protocol_events:
                if event.timestamp > overwrite.timestamp:
                    following = event
                    break

            correlations.append((overwrite, preceding, following))

        return correlations

    def print_correlation_report(self):
        """Print detailed correlation report"""
        print(f"\n{'='*80}")
        print(f"PROTOCOL STATE CORRELATION ANALYSIS: {self.implementation.upper()}")
        print(f"{'='*80}")
        print(f"\nResults directory: {self.results_dir}")
        print(f"Protocol events: {len(self.protocol_events)}")
        print(f"Key overwrites: {len(self.key_overwrites)}")

        # Protocol event timeline
        print(f"\n{'-'*80}")
        print("PROTOCOL EVENT TIMELINE")
        print(f"{'-'*80}")
        print(f"{'Time':<20} {'Protocol State':<35} {'Checkpoint':<25}")
        print(f"{'-'*80}")

        for event in self.protocol_events:
            time_str = event.timestamp.strftime("%H:%M:%S.%f")[:-3]
            print(f"{time_str:<20} {event.state:<35} {event.checkpoint_name[:24]:<25}")

        # Key overwrite correlations
        print(f"\n{'-'*80}")
        print("KEY OVERWRITES CORRELATED WITH PROTOCOL STATES")
        print(f"{'-'*80}")

        correlations = self.correlate_overwrites_with_states()

        for overwrite, preceding, following in correlations:
            time_str = overwrite.timestamp.strftime("%H:%M:%S.%f")[:-3]
            cleared_str = "✓ CLEARED" if overwrite.is_cleared else "⚠ Changed"

            print(f"\n[{time_str}] {overwrite.key_name} {cleared_str}")
            print(f"  Value: {overwrite.new_value[:32]}...")

            if preceding:
                delta = (overwrite.timestamp - preceding.timestamp).total_seconds() * 1000
                print(f"  ← {delta:>8.1f}ms after: {preceding.state}")
                print(f"     Checkpoint: {preceding.checkpoint_name}")

            if following:
                delta = (following.timestamp - overwrite.timestamp).total_seconds() * 1000
                print(f"  → {delta:>8.1f}ms before: {following.state}")
                print(f"     Checkpoint: {following.checkpoint_name}")

            if not preceding and not following:
                print(f"  ⚠ No protocol events found nearby")

    def generate_summary(self) -> Dict:
        """Generate summary statistics"""
        correlations = self.correlate_overwrites_with_states()

        # Group overwrites by preceding state
        overwrites_by_state = defaultdict(list)
        for overwrite, preceding, _ in correlations:
            if preceding:
                overwrites_by_state[preceding.state].append(overwrite)

        summary = {
            'implementation': self.implementation,
            'total_overwrites': len(self.key_overwrites),
            'total_protocol_events': len(self.protocol_events),
            'overwrites_by_state': {}
        }

        for state, overwrites in overwrites_by_state.items():
            summary['overwrites_by_state'][state] = {
                'count': len(overwrites),
                'keys': [ow.key_name for ow in overwrites],
                'cleared_count': sum(1 for ow in overwrites if ow.is_cleared)
            }

        return summary


def compare_implementations(libreswan_analyzer: StateCorrelationAnalyzer,
                           strongswan_analyzer: StateCorrelationAnalyzer):
    """Compare protocol state correlations between implementations"""
    print(f"\n{'='*80}")
    print("IMPLEMENTATION COMPARISON: KEY OVERWRITE TRIGGERS")
    print(f"{'='*80}")

    lib_summary = libreswan_analyzer.generate_summary()
    sw_summary = strongswan_analyzer.generate_summary()

    # Compare which states trigger overwrites
    lib_states = set(lib_summary['overwrites_by_state'].keys())
    sw_states = set(sw_summary['overwrites_by_state'].keys())

    common_states = lib_states & sw_states
    lib_only = lib_states - sw_states
    sw_only = sw_states - lib_states

    print(f"\nCommon trigger states ({len(common_states)}):")
    for state in sorted(common_states):
        lib_count = lib_summary['overwrites_by_state'][state]['count']
        sw_count = sw_summary['overwrites_by_state'][state]['count']
        print(f"  {state:<40} | LibreSwan: {lib_count:2d} | strongSwan: {sw_count:2d}")

    if lib_only:
        print(f"\nLibreSwan-only trigger states:")
        for state in sorted(lib_only):
            count = lib_summary['overwrites_by_state'][state]['count']
            keys = ', '.join(lib_summary['overwrites_by_state'][state]['keys'])
            print(f"  {state:<40} | {count} overwrites ({keys})")

    if sw_only:
        print(f"\nstrongSwan-only trigger states:")
        for state in sorted(sw_only):
            count = sw_summary['overwrites_by_state'][state]['count']
            keys = ', '.join(sw_summary['overwrites_by_state'][state]['keys'])
            print(f"  {state:<40} | {count} overwrites ({keys})")

    # Key-specific comparison
    print(f"\n{'-'*80}")
    print("KEY-SPECIFIC TRIGGER ANALYSIS")
    print(f"{'-'*80}")

    all_keys = {'SK_ei', 'SK_er', 'ENCR_i', 'ENCR_r'}

    for key_name in sorted(all_keys):
        print(f"\n{key_name}:")

        # LibreSwan triggers
        lib_triggers = []
        for state, data in lib_summary['overwrites_by_state'].items():
            if key_name in data['keys']:
                lib_triggers.append(state)

        # strongSwan triggers
        sw_triggers = []
        for state, data in sw_summary['overwrites_by_state'].items():
            if key_name in data['keys']:
                sw_triggers.append(state)

        print(f"  LibreSwan triggers:  {', '.join(lib_triggers) if lib_triggers else 'None'}")
        print(f"  strongSwan triggers: {', '.join(sw_triggers) if sw_triggers else 'None'}")


def main():
    if len(sys.argv) < 3:
        print("Usage: ./analyze_protocol_state_correlation.py <libreswan_dir> <strongswan_dir>")
        print()
        print("Example:")
        print("  ./analyze_protocol_state_correlation.py \\")
        print("      libreswan/experiment/results/20251020_101402/userspace/left \\")
        print("      strongswan/experiment/results/20251013_135547/userspace/left")
        sys.exit(1)

    libreswan_dir = Path(sys.argv[1])
    strongswan_dir = Path(sys.argv[2])

    if not libreswan_dir.exists():
        print(f"[!] LibreSwan directory not found: {libreswan_dir}")
        sys.exit(1)

    if not strongswan_dir.exists():
        print(f"[!] strongSwan directory not found: {strongswan_dir}")
        sys.exit(1)

    # Analyze LibreSwan
    print("[*] Analyzing LibreSwan...")
    lib_analyzer = StateCorrelationAnalyzer(libreswan_dir, 'libreswan')
    lib_analyzer.parse_dumps()
    lib_analyzer.parse_timing_csv()
    lib_analyzer.print_correlation_report()

    # Analyze strongSwan
    print("\n[*] Analyzing strongSwan...")
    sw_analyzer = StateCorrelationAnalyzer(strongswan_dir, 'strongswan')
    sw_analyzer.parse_dumps()
    sw_analyzer.parse_timing_csv()
    sw_analyzer.print_correlation_report()

    # Compare
    compare_implementations(lib_analyzer, sw_analyzer)


if __name__ == '__main__':
    main()
