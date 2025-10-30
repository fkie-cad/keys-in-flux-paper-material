#!/usr/bin/env python3
"""
compare_key_lifespan.py

Compare key lifespan metrics between LibreSwan and strongSwan implementations.
Analyzes how long cryptographic keys remain in memory before being cleared.

Usage:
    ./compare_key_lifespan.py <libreswan_results_dir> <strongswan_results_dir> [options]

    Example:
    ./compare_key_lifespan.py \
        libreswan/experiment/results/20251017_183133/userspace/left \
        strongswan/experiment/results/20251013_135547/userspace/left
"""

import csv
import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict


class KeyLifespanAnalyzer:
    """Analyzes key lifespan from timing CSV files"""

    TRACKED_KEYS = ['SK_ei', 'SK_er', 'ENCR_i', 'ENCR_r']

    def __init__(self, results_dir: str, impl_name: str):
        """
        Initialize analyzer for a result directory.

        Args:
            results_dir: Path to results/YYYYmmdd_HHMMSS/userspace/left
            impl_name: Implementation name ('LibreSwan' or 'strongSwan')
        """
        self.results_dir = Path(results_dir)
        self.impl_name = impl_name
        self.timing_csv = self._find_timing_csv()
        self.events = defaultdict(list)  # {key_name: [events]}
        self.metrics = {}  # {key_name: metrics_dict}

    def _find_timing_csv(self) -> Optional[Path]:
        """Find timing CSV file (timing_libreswan.csv or timing_strongswan.csv)"""
        for csv_name in ["timing_libreswan.csv", "timing_strongswan.csv"]:
            candidate = self.results_dir / csv_name
            if candidate.exists():
                return candidate
        return None

    def parse_timing_csv(self) -> bool:
        """
        Parse timing CSV and extract key lifecycle events.

        Returns:
            True if successful, False otherwise
        """
        if not self.timing_csv:
            print(f"[ERROR] No timing CSV found in {self.results_dir}", file=sys.stderr)
            return False

        try:
            with open(self.timing_csv, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Handle CSV headers with or without leading spaces
                    event = (row.get('event') or row.get(' event', '')).strip()
                    key_name = (row.get('key_name') or row.get(' key_name', '')).strip()
                    timestamp = (row.get('timestamp') or row.get(' timestamp', '')).strip()
                    address = (row.get('address') or row.get(' address', '')).strip()
                    value = (row.get('value') or row.get(' value', '')).strip()

                    if not key_name or not event or not timestamp:
                        continue

                    # Parse timestamp
                    try:
                        dt = datetime.fromisoformat(timestamp)
                    except:
                        continue

                    # Store event
                    self.events[key_name].append({
                        'event': event,
                        'timestamp': timestamp,
                        'datetime': dt,
                        'address': address,
                        'value': value
                    })

            print(f"[{self.impl_name}] Parsed {len(self.events)} keys from {self.timing_csv.name}")
            return True

        except Exception as e:
            print(f"[ERROR] Failed to parse {self.timing_csv}: {e}", file=sys.stderr)
            return False

    def calculate_metrics(self):
        """Calculate lifespan metrics for each tracked key"""
        for key_name in self.TRACKED_KEYS:
            if key_name not in self.events or not self.events[key_name]:
                self.metrics[key_name] = {
                    'available': False,
                    'reason': 'No watchpoint data'
                }
                continue

            events = sorted(self.events[key_name], key=lambda e: e['datetime'])

            # Find creation event (_set)
            creation_event = next((e for e in events if e['event'].endswith('_set')), None)
            if not creation_event:
                self.metrics[key_name] = {
                    'available': False,
                    'reason': 'No creation event'
                }
                continue

            # Find overwrite events (_overwritten)
            overwrite_events = [e for e in events if e['event'].endswith('_overwritten')]
            if not overwrite_events:
                self.metrics[key_name] = {
                    'available': True,
                    'created': creation_event['timestamp'],
                    'created_dt': creation_event['datetime'],
                    'first_overwrite': None,
                    'final_overwrite': None,
                    'initial_lifespan_s': None,
                    'total_lifespan_s': None,
                    'overwrite_count': 0,
                    'properly_cleared': False,
                    'note': 'Key created but never overwritten'
                }
                continue

            first_overwrite = overwrite_events[0]
            final_overwrite = overwrite_events[-1]

            # Calculate lifespans
            initial_lifespan = (first_overwrite['datetime'] - creation_event['datetime']).total_seconds()
            total_lifespan = (final_overwrite['datetime'] - creation_event['datetime']).total_seconds()

            # Check if properly cleared (all zeros)
            properly_cleared = all(c in '0x' for c in final_overwrite['value'].lower())

            self.metrics[key_name] = {
                'available': True,
                'created': creation_event['timestamp'],
                'created_dt': creation_event['datetime'],
                'first_overwrite': first_overwrite['timestamp'],
                'first_overwrite_dt': first_overwrite['datetime'],
                'final_overwrite': final_overwrite['timestamp'],
                'final_overwrite_dt': final_overwrite['datetime'],
                'initial_lifespan_s': initial_lifespan,
                'total_lifespan_s': total_lifespan,
                'overwrite_count': len(overwrite_events),
                'properly_cleared': properly_cleared,
                'final_value': final_overwrite['value'][:32]  # First 16 bytes
            }

        print(f"[{self.impl_name}] Calculated metrics for {len([m for m in self.metrics.values() if m.get('available')])} keys")


def compare_implementations(libreswan: KeyLifespanAnalyzer, strongswan: KeyLifespanAnalyzer) -> Dict:
    """
    Compare metrics between two implementations.

    Returns:
        Dictionary with comparison results
    """
    comparison = {
        'libreswan_dir': str(libreswan.results_dir),
        'strongswan_dir': str(strongswan.results_dir),
        'keys': {},
        'summary': {}
    }

    for key_name in KeyLifespanAnalyzer.TRACKED_KEYS:
        lib_metrics = libreswan.metrics.get(key_name, {})
        sw_metrics = strongswan.metrics.get(key_name, {})

        comparison['keys'][key_name] = {
            'libreswan': lib_metrics,
            'strongswan': sw_metrics
        }

        # Calculate differences if both available
        if lib_metrics.get('available') and sw_metrics.get('available'):
            if lib_metrics.get('initial_lifespan_s') is not None and sw_metrics.get('initial_lifespan_s') is not None:
                comparison['keys'][key_name]['initial_lifespan_diff_s'] = \
                    lib_metrics['initial_lifespan_s'] - sw_metrics['initial_lifespan_s']

            if lib_metrics.get('total_lifespan_s') is not None and sw_metrics.get('total_lifespan_s') is not None:
                comparison['keys'][key_name]['total_lifespan_diff_s'] = \
                    lib_metrics['total_lifespan_s'] - sw_metrics['total_lifespan_s']

            comparison['keys'][key_name]['overwrite_count_diff'] = \
                lib_metrics['overwrite_count'] - sw_metrics['overwrite_count']

    # Calculate summary statistics
    lib_lifespans = [m['initial_lifespan_s'] for m in libreswan.metrics.values()
                     if m.get('available') and m.get('initial_lifespan_s') is not None]
    sw_lifespans = [m['initial_lifespan_s'] for m in strongswan.metrics.values()
                    if m.get('available') and m.get('initial_lifespan_s') is not None]

    if lib_lifespans and sw_lifespans:
        comparison['summary'] = {
            'libreswan_avg_initial_lifespan_s': sum(lib_lifespans) / len(lib_lifespans),
            'strongswan_avg_initial_lifespan_s': sum(sw_lifespans) / len(sw_lifespans),
            'libreswan_keys_cleared': sum(1 for m in libreswan.metrics.values() if m.get('properly_cleared')),
            'strongswan_keys_cleared': sum(1 for m in strongswan.metrics.values() if m.get('properly_cleared')),
            'libreswan_keys_tracked': len(lib_lifespans),
            'strongswan_keys_tracked': len(sw_lifespans)
        }

    return comparison


def generate_report(comparison: Dict) -> str:
    """Generate formatted ASCII table report"""
    lines = []
    lines.append("=" * 80)
    lines.append("Key Lifespan Comparison: LibreSwan vs strongSwan")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Results:")
    lines.append(f"  LibreSwan:  {comparison['libreswan_dir']}")
    lines.append(f"  strongSwan: {comparison['strongswan_dir']}")
    lines.append("")

    for key_name in KeyLifespanAnalyzer.TRACKED_KEYS:
        key_data = comparison['keys'].get(key_name, {})
        lib = key_data.get('libreswan', {})
        sw = key_data.get('strongswan', {})

        lines.append("-" * 80)
        key_desc = {
            'SK_ei': 'IKE Encryption Key - Initiator',
            'SK_er': 'IKE Encryption Key - Responder',
            'ENCR_i': 'ESP Encryption Key - Initiator',
            'ENCR_r': 'ESP Encryption Key - Responder'
        }
        lines.append(f"{key_name} ({key_desc.get(key_name, 'Unknown')})")
        lines.append("-" * 80)

        # Header
        lines.append(f"{'Metric':<25} {'LibreSwan':<20} {'strongSwan':<20} {'Δ (Difference)':<15}")
        lines.append("─" * 80)

        # Check availability
        if not lib.get('available') and not sw.get('available'):
            lines.append(f"  No data available for {key_name}")
            lines.append("")
            continue

        if not lib.get('available'):
            lines.append(f"  LibreSwan: {lib.get('reason', 'No data')}")
        if not sw.get('available'):
            lines.append(f"  strongSwan: {sw.get('reason', 'No data')}")

        if not (lib.get('available') and sw.get('available')):
            lines.append("")
            continue

        # Timestamps
        lib_created = lib.get('created', 'N/A')[-15:] if lib.get('created') else 'N/A'  # Last 15 chars (time part)
        sw_created = sw.get('created', 'N/A')[-15:] if sw.get('created') else 'N/A'
        lines.append(f"{'Created at':<25} {lib_created:<20} {sw_created:<20} {'-':<15}")

        if lib.get('first_overwrite') and sw.get('first_overwrite'):
            lib_first_ow = lib['first_overwrite'][-15:]
            sw_first_ow = sw['first_overwrite'][-15:]
            lines.append(f"{'First overwrite':<25} {lib_first_ow:<20} {sw_first_ow:<20} {'-':<15}")

        if lib.get('final_overwrite') and sw.get('final_overwrite'):
            lib_final_ow = lib['final_overwrite'][-15:]
            sw_final_ow = sw['final_overwrite'][-15:]
            lines.append(f"{'Final overwrite':<25} {lib_final_ow:<20} {sw_final_ow:<20} {'-':<15}")

        # Lifespans
        if lib.get('initial_lifespan_s') is not None and sw.get('initial_lifespan_s') is not None:
            lib_initial = f"{lib['initial_lifespan_s']:.3f} s"
            sw_initial = f"{sw['initial_lifespan_s']:.3f} s"
            diff = key_data.get('initial_lifespan_diff_s', 0)
            diff_str = f"{diff:+.3f} s"
            lines.append(f"{'Initial lifespan':<25} {lib_initial:<20} {sw_initial:<20} {diff_str:<15}")

        if lib.get('total_lifespan_s') is not None and sw.get('total_lifespan_s') is not None:
            lib_total = f"{lib['total_lifespan_s']:.3f} s"
            sw_total = f"{sw['total_lifespan_s']:.3f} s"
            diff = key_data.get('total_lifespan_diff_s', 0)
            diff_str = f"{diff:+.3f} s"
            lines.append(f"{'Total lifespan':<25} {lib_total:<20} {sw_total:<20} {diff_str:<15}")

        # Overwrite count
        lib_count = str(lib.get('overwrite_count', 0))
        sw_count = str(sw.get('overwrite_count', 0))
        count_diff = key_data.get('overwrite_count_diff', 0)
        count_diff_str = f"{count_diff:+d}" if count_diff != 0 else "0"
        lines.append(f"{'Overwrite count':<25} {lib_count:<20} {sw_count:<20} {count_diff_str:<15}")

        # Properly cleared
        lib_cleared = "✓ Yes" if lib.get('properly_cleared') else "✗ No"
        sw_cleared = "✓ Yes" if sw.get('properly_cleared') else "✗ No"
        lines.append(f"{'Properly cleared':<25} {lib_cleared:<20} {sw_cleared:<20} {'-':<15}")

        lines.append("")

    # Summary
    if comparison.get('summary'):
        lines.append("=" * 80)
        lines.append("Summary")
        lines.append("=" * 80)
        summary = comparison['summary']

        lines.append(f"\nAverage initial lifespan:")
        lines.append(f"  LibreSwan:  {summary['libreswan_avg_initial_lifespan_s']:.3f} s")
        lines.append(f"  strongSwan: {summary['strongswan_avg_initial_lifespan_s']:.3f} s")
        diff = summary['libreswan_avg_initial_lifespan_s'] - summary['strongswan_avg_initial_lifespan_s']
        if diff < 0:
            lines.append(f"  → LibreSwan clears keys {abs(diff):.3f} s faster on average")
        elif diff > 0:
            lines.append(f"  → strongSwan clears keys {diff:.3f} s faster on average")
        else:
            lines.append(f"  → Both implementations have equal average lifespan")

        lines.append(f"\nKeys properly cleared:")
        lines.append(f"  LibreSwan:  {summary['libreswan_keys_cleared']}/{summary['libreswan_keys_tracked']}")
        lines.append(f"  strongSwan: {summary['strongswan_keys_cleared']}/{summary['strongswan_keys_tracked']}")

    lines.append("")
    return "\n".join(lines)


def export_csv(comparison: Dict, output_path: str):
    """Export comparison to CSV file"""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['implementation', 'key_name', 'created', 'first_overwrite', 'final_overwrite',
                         'initial_lifespan_s', 'total_lifespan_s', 'overwrite_count', 'properly_cleared'])

        for key_name in KeyLifespanAnalyzer.TRACKED_KEYS:
            key_data = comparison['keys'].get(key_name, {})

            for impl_name in ['libreswan', 'strongswan']:
                metrics = key_data.get(impl_name, {})
                if not metrics.get('available'):
                    continue

                writer.writerow([
                    impl_name,
                    key_name,
                    metrics.get('created', ''),
                    metrics.get('first_overwrite', ''),
                    metrics.get('final_overwrite', ''),
                    metrics.get('initial_lifespan_s', ''),
                    metrics.get('total_lifespan_s', ''),
                    metrics.get('overwrite_count', 0),
                    'Yes' if metrics.get('properly_cleared') else 'No'
                ])

    print(f"\n[*] CSV exported to: {output_path}")


def export_json(comparison: Dict, output_path: str):
    """Export comparison to JSON file"""
    # Convert datetime objects to strings for JSON serialization
    json_data = json.loads(json.dumps(comparison, default=str))

    with open(output_path, 'w') as f:
        json.dump(json_data, f, indent=2)

    print(f"[*] JSON exported to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Compare key lifespan between LibreSwan and strongSwan implementations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic comparison
  ./compare_key_lifespan.py libreswan_results/ strongswan_results/

  # Export to CSV and JSON
  ./compare_key_lifespan.py libreswan_results/ strongswan_results/ \\
      --csv comparison.csv --json comparison.json

  # Quiet mode (only exports)
  ./compare_key_lifespan.py libreswan_results/ strongswan_results/ \\
      --quiet --csv comparison.csv
        """
    )

    parser.add_argument('libreswan_dir', help='LibreSwan results directory (userspace/left)')
    parser.add_argument('strongswan_dir', help='strongSwan results directory (userspace/left)')
    parser.add_argument('--csv', help='Export comparison to CSV file')
    parser.add_argument('--json', help='Export comparison to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress console output')

    args = parser.parse_args()

    # Initialize analyzers
    libreswan = KeyLifespanAnalyzer(args.libreswan_dir, "LibreSwan")
    strongswan = KeyLifespanAnalyzer(args.strongswan_dir, "strongSwan")

    # Parse timing CSVs
    if not libreswan.parse_timing_csv():
        sys.exit(1)
    if not strongswan.parse_timing_csv():
        sys.exit(1)

    # Calculate metrics
    libreswan.calculate_metrics()
    strongswan.calculate_metrics()

    # Compare implementations
    comparison = compare_implementations(libreswan, strongswan)

    # Generate and display report
    if not args.quiet:
        report = generate_report(comparison)
        print("\n" + report)

    # Export results
    if args.csv:
        export_csv(comparison, args.csv)

    if args.json:
        export_json(comparison, args.json)

    if not args.csv and not args.json and not args.quiet:
        print("\n[*] Tip: Use --csv or --json to export results for further analysis")


if __name__ == "__main__":
    main()
