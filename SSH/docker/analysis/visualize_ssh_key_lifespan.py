#!/usr/bin/env python3
"""
SSH Key Lifespan Visualizer - Generate timeline chart of key lifecycle

This tool creates a visual timeline chart showing when SSH secrets exist in memory
across different lifecycle phases (Handshake, Session, Rekey, Teardown, Cleanup).

The chart displays:
- Green solid lines: Handshake secret (shared_secret K) lifetime
- Blue solid lines: Session keys (cipher_key_in/out) lifetime
- Blue dashed lines: Session keys without rekey scenario
- Red X marks: Targeted secret removal events (m_burn)
- Vertical phase markers: KEXINIT, NEWKEYS, REKEY, DISCONNECT

Usage:
    ./visualize_ssh_key_lifespan.py --timing <timing_csv> --output <chart.png>

Example:
    ./visualize_ssh_key_lifespan.py \
        --timing ../data/lldb_results/timing_dropbear.csv \
        --output dropbear_key_lifespan.png

Input:
    - Timing CSV with columns: secret_name, event_type, timestamp
    - Optional: correlated timeline JSON from correlate_ssh_pcap.py

Output:
    - PNG chart showing key lifespan visualization
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle
    import matplotlib.patches as mpatches
except ImportError:
    print("Error: matplotlib not installed. Install with: pip install matplotlib")
    sys.exit(1)


# Color scheme (matching TLS chart)
COLOR_HANDSHAKE = '#2ecc71'  # Green for handshake secrets
COLOR_SESSION = '#3498db'    # Blue for session keys
COLOR_REMOVAL = '#e74c3c'    # Red for removal events

# Lifecycle phases (X-axis markers)
PHASE_MARKERS = {
    'KEXINIT': 'KI',
    'DH_INIT': 'DI',
    'DH_REPLY': 'DR',
    'NEWKEYS': 'NK',
    'USERAUTH': 'UA',
    'CHANNEL_OPEN': 'CO',
    'APP_DATA': 'AD',
    'REKEY': 'RK',
    'DISCONNECT': 'DC',
}


def parse_timing_csv(timing_file: Path) -> Dict[str, List[Tuple[float, str]]]:
    """
    Parse timing CSV file.

    Expected format:
        secret_name,event_type,timestamp
        shared_secret_k,created,1697645723.456
        shared_secret_k,cleared,1697645724.123
        cipher_key_in,created,1697645723.789
        ...

    Returns:
        Dictionary: {secret_name: [(timestamp, event_type), ...]}
    """
    print(f"[*] Parsing timing CSV: {timing_file}")

    events_by_secret = {}

    if not timing_file.exists():
        print(f"  [!] Timing file not found: {timing_file}")
        return events_by_secret

    with open(timing_file, 'r') as f:
        reader = csv.DictReader(f)

        # Detect format by checking first row headers
        fieldnames = reader.fieldnames

        for row in reader:
            # Handle different CSV formats
            if 'secret_name' in fieldnames:
                # Format: secret_name,event_type,timestamp
                secret_name = row['secret_name']
                event_type = row['event_type']
                timestamp = float(row['timestamp'])
            elif 'key_id' in fieldnames:
                # Format: timestamp,key_id,event,details (Dropbear format)
                secret_name = row['key_id']
                event_type = row['event']
                timestamp = float(row['timestamp'])
            else:
                print(f"  [!] Warning: Unknown CSV format, skipping row")
                continue

            if secret_name not in events_by_secret:
                events_by_secret[secret_name] = []

            events_by_secret[secret_name].append((timestamp, event_type))

    # Sort events by timestamp for each secret
    for secret_name in events_by_secret:
        events_by_secret[secret_name].sort(key=lambda x: x[0])

    print(f"  [+] Loaded {len(events_by_secret)} secrets")
    return events_by_secret


def parse_timeline_json(timeline_file: Path) -> List[Dict]:
    """
    Parse correlated timeline JSON (optional).

    Returns:
        List of timeline events
    """
    print(f"[*] Parsing timeline JSON: {timeline_file}")

    if not timeline_file.exists():
        print(f"  [!] Timeline file not found: {timeline_file}")
        return []

    with open(timeline_file, 'r') as f:
        timeline = json.load(f)

    print(f"  [+] Loaded {len(timeline)} timeline events")
    return timeline


def extract_phase_markers(timeline: List[Dict]) -> List[Tuple[float, str, str]]:
    """
    Extract phase markers from timeline.

    Returns:
        List of (timestamp, phase_name, abbreviation)
    """
    markers = []

    for event in timeline:
        phase = event.get('phase', '').upper()
        summary = event.get('summary', '').upper()
        timestamp = event.get('timestamp', 0)

        # Match against known phases
        for phase_name, abbrev in PHASE_MARKERS.items():
            if phase_name in summary or phase_name in phase:
                markers.append((timestamp, phase_name, abbrev))
                break

    # Remove duplicates, keep first occurrence
    seen = set()
    unique_markers = []
    for marker in markers:
        if marker[1] not in seen:
            unique_markers.append(marker)
            seen.add(marker[1])

    print(f"  [+] Extracted {len(unique_markers)} phase markers")
    return unique_markers


def compute_secret_lifespans(events_by_secret: Dict[str, List[Tuple[float, str]]]) -> Dict[str, List[Tuple[float, float]]]:
    """
    Compute lifespan intervals for each secret.

    A lifespan is from 'created' to 'cleared' or 'freed'.

    Returns:
        Dictionary: {secret_name: [(start_time, end_time), ...]}
    """
    lifespans = {}

    for secret_name, events in events_by_secret.items():
        intervals = []
        start_time = None

        for timestamp, event_type in events:
            if event_type in ['created', 'derived', 'generated']:
                if start_time is None:
                    start_time = timestamp
            elif event_type in ['cleared', 'freed', 'burned', 'removed']:
                if start_time is not None:
                    intervals.append((start_time, timestamp))
                    start_time = None

        # If still active at end, extend to last event + buffer
        if start_time is not None:
            last_timestamp = events[-1][0]
            intervals.append((start_time, last_timestamp + 1.0))

        lifespans[secret_name] = intervals

    return lifespans


def plot_key_lifespan_chart(
    events_by_secret: Dict[str, List[Tuple[float, str]]],
    timeline: Optional[List[Dict]],
    output_file: Path
):
    """
    Generate key lifespan visualization chart.
    """
    print(f"\n[*] Generating chart: {output_file}")

    # Compute lifespans
    lifespans = compute_secret_lifespans(events_by_secret)

    if not lifespans:
        print("  [!] No lifespan data to visualize")
        return

    # Extract phase markers if timeline provided
    phase_markers = []
    if timeline:
        phase_markers = extract_phase_markers(timeline)

    # Normalize timestamps (relative to first event)
    all_timestamps = []
    for events in events_by_secret.values():
        all_timestamps.extend([t for t, _ in events])

    if not all_timestamps:
        print("  [!] No timestamps found")
        return

    time_offset = min(all_timestamps)

    # Normalize lifespans
    normalized_lifespans = {}
    for secret_name, intervals in lifespans.items():
        normalized_lifespans[secret_name] = [
            (start - time_offset, end - time_offset)
            for start, end in intervals
        ]

    # Normalize phase markers
    normalized_markers = [
        (t - time_offset, name, abbrev)
        for t, name, abbrev in phase_markers
    ]

    # Determine time range
    max_time = max(end for intervals in normalized_lifespans.values() for _, end in intervals)

    # Create figure
    fig, ax = plt.subplots(figsize=(14, 6))

    # Y-axis: secret names
    secret_names = sorted(normalized_lifespans.keys())
    y_positions = {name: i for i, name in enumerate(secret_names)}

    # Plot lifespans
    for secret_name, intervals in normalized_lifespans.items():
        y_pos = y_positions[secret_name]

        # Determine color based on secret type
        if 'shared_secret' in secret_name or secret_name == 'dh_K':
            color = COLOR_HANDSHAKE
            linestyle = '-'
            label = 'Handshake Secret'
        elif 'cipher_key' in secret_name or 'mac_key' in secret_name:
            color = COLOR_SESSION
            linestyle = '-'
            label = 'Session Keys'
        else:
            color = '#95a5a6'  # Gray for other secrets
            linestyle = '-'
            label = 'Other'

        # Plot each interval
        for start, end in intervals:
            ax.plot([start, end], [y_pos, y_pos],
                   color=color, linewidth=3, linestyle=linestyle,
                   solid_capstyle='round')

        # Mark removal events with red X
        for timestamp, event_type in events_by_secret[secret_name]:
            if event_type in ['cleared', 'freed', 'burned', 'removed']:
                rel_time = timestamp - time_offset
                ax.plot(rel_time, y_pos, 'x', color=COLOR_REMOVAL,
                       markersize=10, markeredgewidth=2)

    # Add phase markers (vertical lines)
    for timestamp, phase_name, abbrev in normalized_markers:
        ax.axvline(x=timestamp, color='gray', linestyle='--', linewidth=1, alpha=0.5)
        ax.text(timestamp, len(secret_names), abbrev,
               ha='center', va='bottom', fontsize=9, color='gray')

    # Configure axes
    ax.set_yticks(range(len(secret_names)))
    ax.set_yticklabels(secret_names)
    ax.set_xlabel('Time (seconds)', fontsize=12)
    ax.set_ylabel('Secret Name', fontsize=12)
    ax.set_title('SSH Key Lifespan - Dropbear', fontsize=14, fontweight='bold')
    ax.set_xlim(0, max_time * 1.05)
    ax.set_ylim(-0.5, len(secret_names))

    # Grid
    ax.grid(axis='x', alpha=0.3)

    # Legend
    legend_elements = [
        mpatches.Patch(color=COLOR_HANDSHAKE, label='Handshake Secret (K)'),
        mpatches.Patch(color=COLOR_SESSION, label='Session Keys'),
        plt.Line2D([0], [0], marker='x', color='w', markerfacecolor=COLOR_REMOVAL,
                  markersize=10, markeredgewidth=2, label='Key Cleared'),
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=10)

    # Add phase labels at bottom
    if normalized_markers:
        phase_text = "Phases: " + " | ".join([f"{abbrev}={name}" for _, name, abbrev in normalized_markers[:5]])
        fig.text(0.5, 0.02, phase_text, ha='center', fontsize=8, color='gray')

    plt.tight_layout()

    # Save
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"  [+] Chart saved: {output_file}")

    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description='Visualize SSH key lifespan timeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--timing', type=Path, required=True,
                        help='Path to timing CSV file')
    parser.add_argument('--timeline', type=Path,
                        help='Optional: correlated timeline JSON for phase markers')
    parser.add_argument('--output', type=Path, default=Path('ssh_key_lifespan.png'),
                        help='Output PNG file (default: ssh_key_lifespan.png)')

    args = parser.parse_args()

    if not args.timing.exists():
        print(f"Error: Timing file not found: {args.timing}")
        sys.exit(1)

    print("=" * 60)
    print("SSH Key Lifespan Visualizer")
    print("=" * 60)

    # Parse inputs
    events_by_secret = parse_timing_csv(args.timing)

    timeline = None
    if args.timeline and args.timeline.exists():
        timeline = parse_timeline_json(args.timeline)

    # Generate chart
    plot_key_lifespan_chart(events_by_secret, timeline, args.output)

    print("\n" + "=" * 60)
    print("Visualization complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
