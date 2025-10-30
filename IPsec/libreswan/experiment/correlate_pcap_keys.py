#!/usr/bin/env python3
"""
PCAP-Key Lifecycle Correlation Tool for LibreSwan

Correlates network packet capture (PCAP) with key lifecycle events from LLDB monitoring
to show which cryptographic keys were active during packet transmission.

Usage:
    ./correlate_pcap_keys.py results/20251020_101402

Output:
    - Timeline showing packets and key events
    - Correlation matrix showing which keys protected which packets
    - JSON export for further analysis
"""

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import subprocess


@dataclass
class KeyEvent:
    """Represents a key lifecycle event from timing CSV"""
    id: int
    timestamp: datetime
    event: str  # key_set, key_overwritten
    key_name: str  # SK_ei, SK_er, ENCR_i, ENCR_r, etc.
    address: str
    value: str

    def is_set(self) -> bool:
        return self.event.endswith('_set')

    def is_overwrite(self) -> bool:
        return self.event.endswith('_overwritten')

    def is_zeroed(self) -> bool:
        """Check if key was overwritten with zeros (cleared)"""
        return self.is_overwrite() and set(self.value.replace('0', '')) == set()


@dataclass
class Packet:
    """Represents a network packet from PCAP"""
    timestamp: datetime
    direction: str  # 'In' or 'Out'
    protocol: str  # 'isakmp' (IKEv2) or 'ESP'
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    spi: Optional[str]  # For ESP packets
    seq: Optional[int]  # For ESP packets
    length: int
    packet_type: str  # 'ikev2_init', 'ikev2_auth', 'ESP', etc.

    def is_ikev2(self) -> bool:
        return self.protocol == 'isakmp'

    def is_esp(self) -> bool:
        return self.protocol == 'ESP'


@dataclass
class KeyPeriod:
    """Represents a time period when a specific key was active"""
    key_name: str
    key_value: str
    address: str
    start_time: datetime
    end_time: Optional[datetime]
    set_event: KeyEvent
    clear_event: Optional[KeyEvent]
    packets: List[Packet]

    def duration_ms(self) -> Optional[float]:
        if self.end_time:
            delta = self.end_time - self.start_time
            return delta.total_seconds() * 1000
        return None

    def packet_count(self) -> int:
        return len(self.packets)


class TimingParser:
    """Parse timing CSV files"""

    @staticmethod
    def parse_csv(csv_path: Path) -> List[KeyEvent]:
        """Parse timing_libreswan.csv or timing_strongswan.csv"""
        events = []

        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip empty rows
                if not row.get('ID') or not row['ID'].strip():
                    continue

                events.append(KeyEvent(
                    id=int(row['ID'].strip()),
                    timestamp=datetime.fromisoformat(row[' timestamp'].strip()),
                    event=row[' event'].strip(),
                    key_name=row[' key_name'].strip(),
                    address=row[' address'].strip(),
                    value=row[' value'].strip()
                ))

        return sorted(events, key=lambda e: e.timestamp)


class PCAPParser:
    """Parse PCAP files using tcpdump"""

    @staticmethod
    def parse_pcap(pcap_path: Path) -> List[Packet]:
        """Parse PCAP file and extract packet information"""
        packets = []

        # Use tcpdump to parse PCAP (without -v to get single-line output)
        cmd = ['tcpdump', '-r', str(pcap_path), '-nn', '-tttt']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            print(f"[!] Warning: tcpdump failed to parse {pcap_path}")
            return packets

        lines = result.stdout.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            packet = PCAPParser._parse_line(line)
            if packet:
                packets.append(packet)

        return sorted(packets, key=lambda p: p.timestamp)

    @staticmethod
    def _parse_line(line: str) -> Optional[Packet]:
        """Parse a single tcpdump output line"""
        try:
            # Skip continuation lines (indented lines without timestamps)
            if line.startswith('    ') or line.startswith('\t'):
                return None

            parts = line.split()
            if len(parts) < 6:
                return None

            # Parse timestamp: "2025-10-20 10:14:14.142114"
            # Verify first part looks like a date
            if not parts[0][0].isdigit() or '-' not in parts[0]:
                return None

            timestamp_str = f"{parts[0]} {parts[1]}"
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")

            # Parse direction: "In" or "Out" (parts[2] is '?')
            direction = parts[3]

            # Parse protocol and addresses
            # Format: "IP 10.0.0.2.500 > 10.0.0.1.500: isakmp: ..."
            # or: "IP 10.0.0.1 > 10.0.0.2: ESP(spi=0xb1fb34b9,seq=0x1), length 104"

            if parts[4] != 'IP':
                return None

            src = parts[5]
            dst = parts[7].rstrip(':')

            # Parse source IP and port
            if '.' in src:
                src_parts = src.rsplit('.', 1)
                src_ip = src_parts[0]
                src_port = int(src_parts[1]) if len(src_parts) > 1 and src_parts[1].isdigit() else None
            else:
                src_ip = src
                src_port = None

            # Parse destination IP and port
            if '.' in dst:
                dst_parts = dst.rsplit('.', 1)
                dst_ip = dst_parts[0]
                dst_port = int(dst_parts[1]) if len(dst_parts) > 1 and dst_parts[1].isdigit() else None
            else:
                dst_ip = dst
                dst_port = None

            # Parse protocol-specific info
            protocol = parts[8] if len(parts) > 8 else 'unknown'
            spi = None
            seq = None
            packet_type = protocol
            length = 0

            if protocol == 'isakmp:':
                protocol = 'isakmp'
                # Format: "isakmp: parent_sa ikev2_init[I]"
                if len(parts) > 10:
                    packet_type = parts[10].rstrip('[IR]')

            elif protocol.startswith('ESP('):
                protocol = 'ESP'
                # Format: "ESP(spi=0xb1fb34b9,seq=0x1), length 104"
                esp_info = parts[8]
                if 'spi=' in esp_info:
                    spi = esp_info.split('spi=')[1].split(',')[0]
                if 'seq=' in esp_info:
                    seq_str = esp_info.split('seq=')[1].rstrip('),')
                    seq = int(seq_str, 0)  # Parse hex or decimal

                # Parse length
                if 'length' in line:
                    length_idx = parts.index('length')
                    if length_idx + 1 < len(parts):
                        length = int(parts[length_idx + 1])

            return Packet(
                timestamp=timestamp,
                direction=direction,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                spi=spi,
                seq=seq,
                length=length,
                packet_type=packet_type
            )

        except Exception as e:
            print(f"[!] Warning: Failed to parse line: {line[:100]}... ({e})")
            return None


class KeyLifecycleAnalyzer:
    """Analyze key lifecycle and correlate with packets"""

    def __init__(self, events: List[KeyEvent], packets: List[Packet]):
        self.events = events
        self.packets = packets
        self.key_periods: Dict[str, List[KeyPeriod]] = defaultdict(list)

    def analyze(self):
        """Build key periods and assign packets"""
        self._build_key_periods()
        self._assign_packets_to_periods()

    def _build_key_periods(self):
        """Create KeyPeriod objects from key_set and key_overwritten events"""
        # Track current active keys by name
        active_keys: Dict[str, KeyEvent] = {}

        for event in self.events:
            if event.is_set():
                # Check if there's already an active key with this name
                if event.key_name in active_keys:
                    old_set = active_keys[event.key_name]
                    # Close the old period (key was replaced without explicit clear)
                    period = KeyPeriod(
                        key_name=event.key_name,
                        key_value=old_set.value,
                        address=old_set.address,
                        start_time=old_set.timestamp,
                        end_time=event.timestamp,
                        set_event=old_set,
                        clear_event=None,
                        packets=[]
                    )
                    self.key_periods[event.key_name].append(period)

                # Start new period
                active_keys[event.key_name] = event

            elif event.is_overwrite() and event.is_zeroed():
                # Key was cleared (overwritten with zeros)
                if event.key_name in active_keys:
                    set_event = active_keys[event.key_name]
                    period = KeyPeriod(
                        key_name=event.key_name,
                        key_value=set_event.value,
                        address=set_event.address,
                        start_time=set_event.timestamp,
                        end_time=event.timestamp,
                        set_event=set_event,
                        clear_event=event,
                        packets=[]
                    )
                    self.key_periods[event.key_name].append(period)
                    del active_keys[event.key_name]

        # Close any remaining open periods (keys still active at end)
        for key_name, set_event in active_keys.items():
            period = KeyPeriod(
                key_name=key_name,
                key_value=set_event.value,
                address=set_event.address,
                start_time=set_event.timestamp,
                end_time=None,  # Still active
                set_event=set_event,
                clear_event=None,
                packets=[]
            )
            self.key_periods[key_name].append(period)

    def _assign_packets_to_periods(self):
        """Assign each packet to the appropriate key period"""
        for packet in self.packets:
            # IKEv2 packets use SK_ei/SK_er keys
            if packet.is_ikev2():
                self._assign_to_period(packet, 'SK_ei' if packet.direction == 'Out' else 'SK_er')

            # ESP packets use ENCR_i/ENCR_r keys
            elif packet.is_esp():
                self._assign_to_period(packet, 'ENCR_i' if packet.direction == 'Out' else 'ENCR_r')

    def _assign_to_period(self, packet: Packet, key_name: str):
        """Assign a packet to the active key period at its timestamp"""
        if key_name not in self.key_periods:
            return

        for period in self.key_periods[key_name]:
            # Check if packet timestamp falls within this period
            if period.start_time <= packet.timestamp:
                if period.end_time is None or packet.timestamp <= period.end_time:
                    period.packets.append(packet)
                    break

    def print_timeline(self):
        """Print human-readable timeline of events and packets"""
        print("\n" + "="*80)
        print("KEY LIFECYCLE AND PACKET TIMELINE")
        print("="*80)

        # Combine all events and packets into a single timeline
        timeline = []

        for event in self.events:
            timeline.append(('event', event.timestamp, event))

        for packet in self.packets:
            timeline.append(('packet', packet.timestamp, packet))

        timeline.sort(key=lambda x: x[1])

        for item_type, ts, item in timeline:
            time_str = ts.strftime("%H:%M:%S.%f")[:-3]

            if item_type == 'event':
                event: KeyEvent = item
                if event.is_set():
                    print(f"[{time_str}] 🔑 KEY SET     : {event.key_name:8s} = {event.value[:32]}... @ {event.address}")
                elif event.is_zeroed():
                    print(f"[{time_str}] 🗑️  KEY CLEARED : {event.key_name:8s} (overwritten with zeros)")
                else:
                    print(f"[{time_str}] ⚠️  KEY CHANGED : {event.key_name:8s} = {event.value[:32]}...")

            elif item_type == 'packet':
                packet: Packet = item
                dir_arrow = "→" if packet.direction == 'Out' else "←"

                if packet.is_ikev2():
                    print(f"[{time_str}] 📦 IKEv2 {dir_arrow}   : {packet.packet_type} ({packet.src_ip} → {packet.dst_ip})")
                elif packet.is_esp():
                    print(f"[{time_str}] 🔒 ESP   {dir_arrow}   : SPI={packet.spi} seq={packet.seq} len={packet.length}")

    def print_summary(self):
        """Print summary statistics"""
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)

        total_packets = len(self.packets)
        ikev2_packets = sum(1 for p in self.packets if p.is_ikev2())
        esp_packets = sum(1 for p in self.packets if p.is_esp())

        print(f"\nTotal packets: {total_packets}")
        print(f"  - IKEv2 handshake: {ikev2_packets}")
        print(f"  - ESP encrypted:   {esp_packets}")

        print(f"\nKey lifecycle periods:")
        for key_name in sorted(self.key_periods.keys()):
            periods = self.key_periods[key_name]
            print(f"\n  {key_name}:")
            for i, period in enumerate(periods, 1):
                duration = period.duration_ms()
                duration_str = f"{duration:.1f}ms" if duration else "ongoing"
                packet_count = period.packet_count()
                print(f"    Period {i}: {duration_str:>12s} | {packet_count:3d} packets | value={period.key_value[:32]}...")

                if packet_count > 0:
                    first_packet_delta = (period.packets[0].timestamp - period.start_time).total_seconds() * 1000
                    print(f"              First packet after: {first_packet_delta:.1f}ms")

                    if period.end_time:
                        last_packet_delta = (period.end_time - period.packets[-1].timestamp).total_seconds() * 1000
                        print(f"              Last packet before clear: {last_packet_delta:.1f}ms")

        # Security analysis
        print("\n" + "="*80)
        print("SECURITY ANALYSIS")
        print("="*80)

        # Check ESP key handling
        encr_i_periods = self.key_periods.get('ENCR_i', [])
        encr_r_periods = self.key_periods.get('ENCR_r', [])
        esp_pkts = [p for p in self.packets if p.is_esp()]

        if esp_pkts and encr_i_periods:
            first_esp_time = esp_pkts[0].timestamp
            first_encr_clear = encr_i_periods[0].end_time if encr_i_periods[0].end_time else None

            if first_encr_clear and first_esp_time > first_encr_clear:
                delta_ms = (first_esp_time - first_encr_clear).total_seconds() * 1000
                print(f"\n✓ ESP encryption keys cleared {delta_ms:.1f}ms BEFORE ESP traffic")
                print("  This indicates keys were removed from userspace memory before use,")
                print("  likely handled by kernel (XFRM) after derivation.")
            elif encr_i_periods[0].packet_count > 0:
                print(f"\n⚠ ESP packets sent while keys present in userspace memory")
                print("  Keys were protected {encr_i_periods[0].packet_count} ESP packets")
            else:
                print(f"\n✓ No ESP packets correlated with userspace key lifetime")

        # Check IKE key handling
        sk_ei_periods = self.key_periods.get('SK_ei', [])
        sk_er_periods = self.key_periods.get('SK_er', [])
        ikev2_pkts = [p for p in self.packets if p.is_ikev2()]

        if ikev2_pkts and (sk_ei_periods or sk_er_periods):
            # Count unique IKEv2 packets protected by either SK_ei or SK_er
            protected_timestamps = set()
            for period in sk_ei_periods + sk_er_periods:
                for pkt in period.packets:
                    protected_timestamps.add(pkt.timestamp)

            total_protected = len(protected_timestamps)
            total_ikev2 = len(ikev2_pkts)

            print(f"\nIKE encryption keys protected {total_protected}/{total_ikev2} IKEv2 packets")
            if total_protected < total_ikev2:
                unprotected = total_ikev2 - total_protected
                print(f"  {unprotected} IKEv2 packets sent before or after key lifetime")

    def export_json(self, output_path: Path):
        """Export correlation data to JSON"""
        data = {
            'metadata': {
                'total_events': len(self.events),
                'total_packets': len(self.packets),
                'ikev2_packets': sum(1 for p in self.packets if p.is_ikev2()),
                'esp_packets': sum(1 for p in self.packets if p.is_esp()),
            },
            'key_periods': {}
        }

        for key_name, periods in self.key_periods.items():
            data['key_periods'][key_name] = []
            for period in periods:
                period_data = {
                    'key_value': period.key_value,
                    'address': period.address,
                    'start_time': period.start_time.isoformat(),
                    'end_time': period.end_time.isoformat() if period.end_time else None,
                    'duration_ms': period.duration_ms(),
                    'packet_count': period.packet_count(),
                    'packets': [
                        {
                            'timestamp': p.timestamp.isoformat(),
                            'direction': p.direction,
                            'protocol': p.protocol,
                            'type': p.packet_type,
                            'spi': p.spi,
                            'seq': p.seq,
                            'length': p.length
                        }
                        for p in period.packets
                    ]
                }
                data['key_periods'][key_name].append(period_data)

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[✓] Exported correlation data to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: ./correlate_pcap_keys.py <results_directory>")
        print("Example: ./correlate_pcap_keys.py results/20251020_101402")
        sys.exit(1)

    results_dir = Path(sys.argv[1])

    if not results_dir.exists():
        print(f"[!] Error: Results directory not found: {results_dir}")
        sys.exit(1)

    # Find timing CSV (auto-detect libreswan vs strongswan)
    timing_csv = results_dir / "userspace" / "left" / "timing_libreswan.csv"
    if not timing_csv.exists():
        timing_csv = results_dir / "userspace" / "left" / "timing_strongswan.csv"

    if not timing_csv.exists():
        print(f"[!] Error: No timing CSV found in {results_dir}/userspace/left/")
        sys.exit(1)

    # Find PCAP
    pcap_file = results_dir / "network" / "left.pcap"
    if not pcap_file.exists():
        print(f"[!] Error: PCAP file not found: {pcap_file}")
        sys.exit(1)

    print(f"[*] Parsing timing data from: {timing_csv}")
    events = TimingParser.parse_csv(timing_csv)
    print(f"    Loaded {len(events)} key lifecycle events")

    print(f"[*] Parsing PCAP from: {pcap_file}")
    packets = PCAPParser.parse_pcap(pcap_file)
    print(f"    Loaded {len(packets)} packets")

    # Analyze and correlate
    print(f"[*] Analyzing key lifecycle and packet correlation...")
    analyzer = KeyLifecycleAnalyzer(events, packets)
    analyzer.analyze()

    # Print results
    analyzer.print_timeline()
    analyzer.print_summary()

    # Export JSON
    output_json = results_dir / "correlation.json"
    analyzer.export_json(output_json)


if __name__ == '__main__':
    main()
