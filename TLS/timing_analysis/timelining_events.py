import csv
import pyshark
import os
import glob
from datetime import datetime, timedelta
import argparse
import tempfile
import re

# --- ANSI Colors for Terminal Output ---
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

def clean_summary_for_pattern(summary):
    """Removes ANSI color codes from a string."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', summary)

def create_temp_keylog_from_csv(keylog_csv_path):
    """Creates a temporary NSS keylog file from a CSV."""
    keylog_lines = []
    try:
        with open(keylog_csv_path, 'r', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2 and 'line' not in row[1]:
                    keylog_lines.append(row[1])
        if not keylog_lines: return None
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.log', prefix='keylog_') as temp_f:
            temp_f.write('\n'.join(keylog_lines))
            return temp_f.name
    except Exception as e:
        print(f"❌ Error creating temporary keylog file from '{keylog_csv_path}': {e}")
        return None

def load_keylog_secrets(keylog_path, tls_version):
    """Reads a keylog file and extracts secrets."""
    secrets_map, secrets_set = {}, set()
    label_map = {}
    if tls_version == '1.3':
        label_map = {
            'CLIENT_HANDSHAKE_TRAFFIC_SECRET': 'C_HS', 'SERVER_HANDSHAKE_TRAFFIC_SECRET': 'S_HS',
            'CLIENT_TRAFFIC_SECRET_0': 'C_AP', 'SERVER_TRAFFIC_SECRET_0': 'S_AP',
        }
    elif tls_version == '1.2':
        label_map = {'CLIENT_RANDOM': 'MS'}
    else:
        return {}, set()

    try:
        with open(keylog_path, 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip(): continue
                parts = line.strip().split()
                if len(parts) == 3 and parts[0] in label_map:
                    nss_label, secret_hex = parts[0], parts[2]
                    short_label = label_map[nss_label]
                    secrets_map[short_label] = bytes.fromhex(secret_hex)
                    secrets_set.add(secret_hex)
    except Exception as e:
        print(f"❌ Error reading keylog file: {e}")
    print(f"✅ Mapped {len(secrets_map)} unique TLS {tls_version} secrets.")
    return secrets_map, secrets_set

def process_memory_dumps(dump_dir, secrets_map, tls_version):
    """Reads all memory dumps from a directory."""
    secret_order = []
    if tls_version == '1.3':
        secret_order = ['C_HS', 'S_HS', 'C_AP', 'S_AP']
    elif tls_version == '1.2':
        secret_order = ['MS']
    else:
        return []

    all_dumps = []
    for dump_path in glob.glob(os.path.join(dump_dir, '*.dump')):
        filename = os.path.basename(dump_path)
        try:
            parts = filename.replace('.dump', '').split('_')
            ts = datetime.strptime(f"{parts[0]}{parts[1]}.{parts[2]}", '%Y%m%d%H%M%S.%f')
            dump_type = "_".join(parts[3:])
            with open(dump_path, 'rb') as f:
                dump_content = f.read()
            found_labels = [label for label in secret_order if secrets_map.get(label) and secrets_map[label] in dump_content]
            summary_parts = [f"{colors.GREEN if label in found_labels else colors.RED}{label}{colors.ENDC}" for label in secret_order]
            summary = f"Secrets Found in {dump_type}: ({', '.join(summary_parts)})"
            all_dumps.append({'timestamp': ts, 'source': 'DUMP', 'summary': summary, 'found_in_dump': found_labels, 'dump_type': dump_type})
        except (IndexError, ValueError) as e:
            print(f"⚠️ Warning: Could not parse dump filename '{filename}'. Skipping. Error: {e}")
    return all_dumps

def process_csv_with_state_tracking(csv_path, valid_secrets_set):
    """Interprets state changes in the timing CSV, which only contains logs of the secrets WPs."""
    csv_events, label_states = [], {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = {k.strip(): v.strip() for k, v in row.items()}
            try:
                ts, label, csv_secret = datetime.fromisoformat(row['timestamp']), row['label'], row['secret'].replace(' ', '')
                is_valid, previous_state = csv_secret in valid_secrets_set, label_states.get(label)
                event_type = None
                if is_valid and previous_state != 'LOGGED':
                    event_type, label_states[label] = "Key Logged", 'LOGGED'
                elif not is_valid and previous_state == 'LOGGED':
                    event_type, label_states[label] = "Key Removed", 'REMOVED'
                if event_type:
                    csv_events.append({'timestamp': ts, 'source': 'CSV', 'summary': f"{event_type}: {label}", 'csv_label': label, 'csv_action': event_type.split(' ')[1]})
            except (ValueError, KeyError) as e:
                print(f"⚠️ Warning: Could not parse row in CSV: {row}. Error: {e}")
    return csv_events

def process_pcap(pcap_path, keylog_path):
    """Processes the PCAP to extract decrypted TLS messages."""
    pcap_events = []
    try:
        cap = pyshark.FileCapture(pcap_path, override_prefs={'tls.keylog_file': keylog_path}, display_filter='tcp.port == 4433 or tcp.port == 4432')
        for pkt in cap:
            if 'tls' in pkt:
                summary = "Decrypted TLS Record"
                try:
                    content_type = pkt.tls.record_content_type
                    if content_type == '23': summary = f"Decrypted Application Data ({pkt.tls.record_length} bytes)"
                    elif hasattr(pkt.tls, 'handshake_type'): summary = f"TLS Handshake: {pkt.tls.handshake_type.showname}"
                    elif content_type == '20': summary = "TLS Change Cipher Spec"
                    elif content_type == '21': summary = f"TLS Alert: {getattr(pkt.tls, 'alert_description_showname', 'Unknown Alert')}"
                except AttributeError: pass
                pcap_events.append({'timestamp': pkt.sniff_time, 'source': 'PCAP', 'summary': f"Packet #{pkt.number}: {summary}"})
        cap.close()
    except Exception as e:
        print(f"❌ Error processing PCAP file: {e}")
    return pcap_events

def adjust_event_timeline(events):
    """
    Filters dump events to ensure only the logically relevant ones are included.
    """
    pcap_events = [e for e in events if e['source'] == 'PCAP']
    csv_events = [e for e in events if e['source'] == 'CSV']
    dump_events = [e for e in events if e['source'] == 'DUMP']

    # Find the timestamp of the last network event to define the boundary for cleanup.
    last_pcap_time = max(e['timestamp'] for e in pcap_events) if pcap_events else datetime.min

    # Separate cleanup dumps from all other types.
    all_cleanup_dumps = [d for d in dump_events if 'cleanup' in d.get('dump_type', '').lower()]
    other_dumps = [d for d in dump_events if 'cleanup' not in d.get('dump_type', '').lower()]

    selected_cleanups = []
    if all_cleanup_dumps:
        # Only consider cleanup dumps that happened after the last network packet.
        post_network_cleanups = [d for d in all_cleanup_dumps if d['timestamp'] > last_pcap_time]

        # From that valid set, select the first 'pre' and the last 'post' (in case multiple stages occur).
        pre_cleanups = sorted([d for d in post_network_cleanups if 'pre' in d.get('dump_type', '')], key=lambda x: x['timestamp'])
        post_cleanups = sorted([d for d in post_network_cleanups if 'post' in d.get('dump_type', '')], key=lambda x: x['timestamp'])

        if pre_cleanups:
            selected_cleanups.append(pre_cleanups[0])
        if post_cleanups:
            selected_cleanups.append(post_cleanups[-1])
        
        if len(post_network_cleanups) < len(all_cleanup_dumps):
             print(f"ℹ️ Ignoring {len(all_cleanup_dumps) - len(post_network_cleanups)} cleanup dump(s) that occurred before network activity ended.")

    # Re-combine all events. The main function's sort will place them correctly.
    return pcap_events + csv_events + other_dumps + selected_cleanups

def main():
    parser = argparse.ArgumentParser(description="Analyze and export unique event timeline patterns from TLS library runs.")
    parser.add_argument('library_path', help="Path to the library directory containing run subdirectories.")
    parser.add_argument('--export-file', help="Path to CSV file to export unique timeline patterns.", default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.library_path):
        print(f"❌ Error: Library directory not found at '{args.library_path}'")
        return

    all_events_for_export = []
    library_name = os.path.basename(os.path.normpath(args.library_path))
    run_directories = sorted(glob.glob(os.path.join(args.library_path, '*_run_*')))
    if not run_directories:
        print(f"❌ Error: No run directories found in '{args.library_path}'")
        return
    
    print(f"Found {len(run_directories)} total run directories for library '{library_name}'. Starting analysis...")
    patterns_log = {'1.2': {}, '1.3': {}}

    for run_dir in run_directories:
        run_name = os.path.basename(run_dir)
        tls_version = '1.2' if '_12_' in run_name else '1.3' if '_13_' in run_name else None
        if not tls_version: continue
        
        print(f"\n{'='*25} Processing Run: {run_name} (TLS {tls_version}) {'='*25}")
        timing_csv = next(iter(glob.glob(os.path.join(run_dir, 'timing_*.csv'))), None)
        pcap_file = os.path.join(run_dir, 'run_data', 'traffic.pcap')
        keylog_csv = os.path.join(run_dir, 'keylog.csv')
        if not all([timing_csv, os.path.exists(pcap_file), os.path.exists(keylog_csv)]):
            print(f"⚠️ Warning: Missing one or more data files in '{run_dir}'. Skipping.")
            continue

        temp_keylog_path = None
        try:
            temp_keylog_path = create_temp_keylog_from_csv(keylog_csv)
            if not temp_keylog_path: continue
            
            secrets_map, valid_secrets_set = load_keylog_secrets(temp_keylog_path, tls_version)
            all_events = (
                process_csv_with_state_tracking(timing_csv, valid_secrets_set) +
                process_pcap(pcap_file, temp_keylog_path) +
                process_memory_dumps(run_dir, secrets_map, tls_version)
            )
            # This function now only filters, it does not re-order.
            all_events = adjust_event_timeline(all_events)

            def normalize_event_for_pattern(ev):
                src = ev.get('source')
                if src == 'DUMP':
                    s = (ev.get('dump_type', '') or '').lower()
                    dt = 'key_update' if 'key_update' in s else 'abort' if 'abort' in s else 'shutdown' if 'shutdown' in s else 'cleanup' if 'cleanup' in s else s
                    labels = ','.join(sorted(ev.get('found_in_dump', [])))
                    return f"DUMP:{dt}:({labels})"
                return f"{src}:{clean_summary_for_pattern(ev.get('summary',''))}"

            # The final sort now happens here, on the filtered but chronologically accurate event list.
            all_events.sort(key=lambda ev: (ev['timestamp'], {'PCAP': 0, 'CSV': 1, 'DUMP': 2}.get(ev.get('source'), 9), ev.get('dump_type', '')))
            current_pattern = tuple(normalize_event_for_pattern(e) for e in all_events)
            pretty_pattern = tuple(f"{event['source']}: {event['summary']}" for event in all_events)
            
            if current_pattern not in patterns_log[tls_version]:
                print(f"\n✨ {colors.GREEN}New TLS {tls_version} event pattern detected from '{run_name}'.{colors.ENDC}")
                patterns_log[tls_version][current_pattern] = {'count': 1, 'first_run': run_name, 'pretty': pretty_pattern}
                if args.export_file:
                    for event in all_events:
                        all_events_for_export.append({
                            'library': library_name, 'run_name': run_name, 'tls_version': tls_version,
                            'timestamp': event['timestamp'].isoformat(), 'source': event['source'],
                            'summary': clean_summary_for_pattern(event['summary']),
                            'csv_label': event.get('csv_label', ''), 'csv_action': event.get('csv_action', ''),
                            'found_in_dump': " ".join(event.get('found_in_dump', [])), 'dump_type': event.get('dump_type', '')
                        })
            else:
                patterns_log[tls_version][current_pattern]['count'] += 1
                print(f"\n✅ {colors.BLUE}This run matches a TLS {tls_version} pattern first seen in '{patterns_log[tls_version][current_pattern]['first_run']}'.{colors.ENDC}")
        finally:
            if temp_keylog_path and os.path.exists(temp_keylog_path):
                os.remove(temp_keylog_path)

    print(f"\n\n{'='*30} 📈 Analysis Summary 📈 {'='*30}")
    for tls_version, version_log in patterns_log.items():
        if not version_log: continue
        print(f"\n{colors.BLUE}TLS {tls_version} Analysis:{colors.ENDC}")
        print(f"  - Found {len(version_log)} unique event pattern(s) across {sum(p['count'] for p in version_log.values())} run(s).")
        for i, (pattern, data) in enumerate(version_log.items()):
            print(f"    - {colors.GREEN}Pattern #{i+1}{colors.ENDC}: Occurred: {data['count']} time(s), First seen in: {data['first_run']}")
            print(f"      - Event Sequence:")
            for event_summary in data.get('pretty', pattern):
                print(f"        - {event_summary}")
    
    if args.export_file and all_events_for_export:
        print(f"\n\n{'='*30} 📊 Exporting Data 📊 {'='*30}")
        try:
            with open(args.export_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=all_events_for_export[0].keys())
                writer.writeheader()
                writer.writerows(all_events_for_export)
            print(f"✅ Successfully exported {len(all_events_for_export)} events from unique patterns to '{args.export_file}'")
        except Exception as e:
            print(f"❌ Error exporting data: {e}")
    
if __name__ == "__main__":
    main()