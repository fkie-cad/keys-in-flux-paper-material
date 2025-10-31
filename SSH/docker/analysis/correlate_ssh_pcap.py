#!/usr/bin/env python3
"""
SSH PCAP Correlator - Correlate SSH protocol messages with LLDB events

This tool parses SSH PCAP files and correlates them with LLDB monitoring events
to create a unified timeline showing the relationship between network protocol
messages and internal key lifecycle events.

Usage:
    ./correlate_ssh_pcap.py --pcap <capture.pcap> --events <events.log> [--output timeline.json]

Example:
    ./correlate_ssh_pcap.py \
        --pcap ../data/captures/server_20251018_184203.pcap \
        --events ../data/lldb_results/dropbear_events.log \
        --output correlated_timeline.json

Input:
    - PCAP file with SSH traffic
    - LLDB events log (events.log or events.jsonl)

Output:
    - JSON file with correlated timeline
    - Each event includes: timestamp, source (PCAP/LLDB), phase, summary
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    from scapy.all import rdpcap, TCP
    from scapy.layers.inet import IP
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)


# SSH protocol message types (from RFC 4253)
SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_CLOSE = 97

SSH_MSG_NAMES = {
    1: "DISCONNECT",
    2: "IGNORE",
    3: "UNIMPLEMENTED",
    4: "DEBUG",
    5: "SERVICE_REQUEST",
    6: "SERVICE_ACCEPT",
    20: "KEXINIT",
    21: "NEWKEYS",
    30: "KEXDH_INIT / KEX_ECDH_INIT",
    31: "KEXDH_REPLY / KEX_ECDH_REPLY",
    50: "USERAUTH_REQUEST",
    51: "USERAUTH_FAILURE",
    52: "USERAUTH_SUCCESS",
    90: "CHANNEL_OPEN",
    91: "CHANNEL_OPEN_CONFIRMATION",
    93: "CHANNEL_WINDOW_ADJUST",
    94: "CHANNEL_DATA",
    97: "CHANNEL_CLOSE",
}

# Lifecycle phase mapping
PHASE_MAPPING = {
    'KEXINIT': 'HANDSHAKE',
    'KEXDH_INIT': 'HANDSHAKE',
    'KEX_ECDH_INIT': 'HANDSHAKE',
    'KEXDH_REPLY': 'HANDSHAKE',
    'KEX_ECDH_REPLY': 'HANDSHAKE',
    'NEWKEYS': 'HANDSHAKE',
    'gen_new_keys': 'HANDSHAKE',
    'kex_comb_key': 'HANDSHAKE',
    'SHARED_SECRET': 'HANDSHAKE',

    'USERAUTH_REQUEST': 'AUTH',
    'USERAUTH_SUCCESS': 'AUTH',
    'USERAUTH_FAILURE': 'AUTH',

    'CHANNEL_OPEN': 'SESSION',
    'CHANNEL_DATA': 'SESSION',
    'switch_keys': 'SESSION',

    'kexinitialise': 'REKEY',
    'REKEY': 'REKEY',

    'DISCONNECT': 'TEARDOWN',
    'CHANNEL_CLOSE': 'TEARDOWN',
    'abort': 'TEARDOWN',
    'dropbear_exit': 'TEARDOWN',

    'm_burn': 'CLEANUP',
    'session_cleanup': 'CLEANUP',
    'cleanup_keys': 'CLEANUP',
}


def parse_pcap(pcap_file: Path) -> List[Dict[str, Any]]:
    """
    Parse SSH PCAP file and extract protocol messages.

    Returns:
        List of events: [{timestamp, source, phase, summary, msg_type, direction, ...}]
    """
    print(f"[*] Parsing PCAP: {pcap_file}")

    try:
        packets = rdpcap(str(pcap_file))
    except Exception as e:
        print(f"  [!] Error reading PCAP: {e}")
        return []

    events = []
    ssh_streams = {}  # Track SSH version exchange per stream

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        payload = bytes(tcp.payload)

        if not payload:
            continue

        # Get stream identifier
        if pkt.haslayer(IP):
            stream_id = f"{pkt[IP].src}:{tcp.sport}-{pkt[IP].dst}:{tcp.dport}"
        else:
            stream_id = f"unknown:{tcp.sport}-{tcp.dport}"

        timestamp = float(pkt.time)

        # Check for SSH version exchange (plain text at start)
        if payload.startswith(b'SSH-'):
            version_line = payload.split(b'\r\n')[0].decode('ascii', errors='ignore')
            ssh_streams[stream_id] = True
            events.append({
                'timestamp': timestamp,
                'source': 'PCAP',
                'phase': 'HANDSHAKE',
                'summary': f"SSH Version Exchange: {version_line}",
                'msg_type': 'VERSION',
                'direction': 'C->S' if tcp.dport == 22 else 'S->C',
                'stream': stream_id,
            })
            continue

        # Skip if stream not identified as SSH
        if stream_id not in ssh_streams:
            continue

        # Parse SSH binary protocol messages
        # SSH packet format: [packet_length(4)][padding_length(1)][payload][padding][MAC]
        # After version exchange, all messages are encrypted except the first few KEX messages

        # Try to parse unencrypted KEX messages (first packet after version exchange)
        if len(payload) >= 6:
            try:
                # SSH packet: [length:4][padding_len:1][type:1][payload...]
                # Note: Length includes padding_len + payload + padding (not including MAC)
                packet_length = int.from_bytes(payload[0:4], 'big')
                padding_length = payload[4]
                msg_type = payload[5]

                # Basic sanity check
                if msg_type in SSH_MSG_NAMES and packet_length < 35000:  # Reasonable max
                    msg_name = SSH_MSG_NAMES[msg_type]
                    phase = PHASE_MAPPING.get(msg_name.split(' /')[0], 'UNKNOWN')

                    events.append({
                        'timestamp': timestamp,
                        'source': 'PCAP',
                        'phase': phase,
                        'summary': f"SSH {msg_name}",
                        'msg_type': msg_name,
                        'msg_type_num': msg_type,
                        'direction': 'C->S' if tcp.dport == 22 else 'S->C',
                        'packet_length': packet_length,
                        'stream': stream_id,
                    })
            except (IndexError, ValueError):
                # Likely encrypted or malformed
                pass

    print(f"  [+] Extracted {len(events)} SSH protocol messages")
    return events


def parse_lldb_events(events_file: Path) -> List[Dict[str, Any]]:
    """
    Parse LLDB events log (events.log or events.jsonl).

    Returns:
        List of events: [{timestamp, source, phase, summary, event_type, ...}]
    """
    print(f"[*] Parsing LLDB events: {events_file}")

    events = []

    if not events_file.exists():
        print(f"  [!] Events file not found: {events_file}")
        return events

    with open(events_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # Try JSON format first (events.jsonl)
            if line.startswith('{'):
                try:
                    event = json.loads(line)
                    events.append({
                        'timestamp': event.get('timestamp', 0),
                        'source': 'LLDB',
                        'phase': infer_phase(event),
                        'summary': event.get('summary', event.get('event', 'Unknown')),
                        'event_type': event.get('event', event.get('type', 'UNKNOWN')),
                        'details': event,
                    })
                    continue
                except json.JSONDecodeError:
                    pass

            # Try plain log format
            # Example: [1697645723.456] GEN_NEW_KEYS: Generating new keys...
            match = re.match(r'\[([0-9.]+)\]\s+(\w+):\s+(.+)', line)
            if match:
                timestamp_str, event_type, message = match.groups()
                timestamp = float(timestamp_str)

                events.append({
                    'timestamp': timestamp,
                    'source': 'LLDB',
                    'phase': PHASE_MAPPING.get(event_type, 'UNKNOWN'),
                    'summary': f"{event_type}: {message}",
                    'event_type': event_type,
                })
                continue

            # Try alternative format: timestamp event message
            parts = line.split(None, 2)
            if len(parts) >= 2:
                try:
                    timestamp = float(parts[0])
                    event_type = parts[1]
                    message = parts[2] if len(parts) > 2 else ""

                    events.append({
                        'timestamp': timestamp,
                        'source': 'LLDB',
                        'phase': PHASE_MAPPING.get(event_type, 'UNKNOWN'),
                        'summary': f"{event_type}: {message}",
                        'event_type': event_type,
                    })
                except ValueError:
                    pass

    print(f"  [+] Loaded {len(events)} LLDB events")
    return events


def infer_phase(event: Dict[str, Any]) -> str:
    """
    Infer lifecycle phase from event details.
    """
    event_type = event.get('event', event.get('type', '')).upper()
    summary = event.get('summary', '').upper()

    # Check against mapping
    for key, phase in PHASE_MAPPING.items():
        if key.upper() in event_type or key.upper() in summary:
            return phase

    return 'UNKNOWN'


def merge_timelines(pcap_events: List[Dict], lldb_events: List[Dict]) -> List[Dict]:
    """
    Merge PCAP and LLDB events into single timeline sorted by timestamp.
    """
    all_events = pcap_events + lldb_events
    all_events.sort(key=lambda e: e['timestamp'])

    print(f"\n[*] Merged timeline: {len(all_events)} total events")
    print(f"    PCAP events: {len(pcap_events)}")
    print(f"    LLDB events: {len(lldb_events)}")

    return all_events


def normalize_timeline(events: List[Dict]) -> List[Dict]:
    """
    Normalize timeline by converting timestamps to relative offsets.
    """
    if not events:
        return events

    start_time = events[0]['timestamp']

    for event in events:
        event['relative_time'] = event['timestamp'] - start_time

    return events


def export_timeline(timeline: List[Dict], output_file: Path):
    """
    Export timeline to JSON file.
    """
    print(f"\n[*] Exporting timeline to: {output_file}")

    with open(output_file, 'w') as f:
        json.dump(timeline, f, indent=2)

    print(f"  [+] Wrote {len(timeline)} events")


def print_summary(timeline: List[Dict]):
    """
    Print summary statistics.
    """
    phase_counts = {}
    source_counts = {'PCAP': 0, 'LLDB': 0}

    for event in timeline:
        phase = event.get('phase', 'UNKNOWN')
        source = event.get('source', 'UNKNOWN')

        phase_counts[phase] = phase_counts.get(phase, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1

    print("\n" + "=" * 60)
    print("Timeline Summary")
    print("=" * 60)

    print("\nEvents by source:")
    for source, count in sorted(source_counts.items()):
        print(f"  {source:10s}: {count:4d}")

    print("\nEvents by phase:")
    for phase, count in sorted(phase_counts.items()):
        print(f"  {phase:15s}: {count:4d}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Correlate SSH PCAP with LLDB events',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--pcap', type=Path, required=True,
                        help='Path to SSH PCAP file')
    parser.add_argument('--events', type=Path, required=True,
                        help='Path to LLDB events log (events.log or events.jsonl)')
    parser.add_argument('--output', type=Path, default=Path('correlated_timeline.json'),
                        help='Output JSON file (default: correlated_timeline.json)')

    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    if not args.events.exists():
        print(f"Error: Events file not found: {args.events}")
        sys.exit(1)

    print("=" * 60)
    print("SSH PCAP Correlator")
    print("=" * 60)

    # Parse inputs
    pcap_events = parse_pcap(args.pcap)
    lldb_events = parse_lldb_events(args.events)

    # Merge and normalize
    timeline = merge_timelines(pcap_events, lldb_events)
    timeline = normalize_timeline(timeline)

    # Export
    export_timeline(timeline, args.output)

    # Summary
    print_summary(timeline)


if __name__ == "__main__":
    main()
